package vulnclaw;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.EnhancedCapability;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * VULNCLAW ↔ Burp 扩展桥 1.0.6 (final: Montoya 直接扫描 + mini HTTP server)
 *
 * 修复 Burp 2026.7.3 REST API 残缺（/scan/{id}/issues 全 500 + REST pipeline 不触发 AuditIssueHandler）。
 * Python 端通过桥的 mini HTTP server (com.sun.net.httpserver, 端口 18181) 调用：
 *   POST /vulnclaw/scan  body: {"urls":["http://..."], "wait":true, "timeout_s":300}
 *     → 桥内部 api.scanner().startAudit(AuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
 *     → audit.addRequest(HttpRequest.httpRequestFromUrl(url))
 *     → 等待 audit 完成
 *     → 返回 {"status":"ok","issue_count":N,"issues":[{...},...]}
 *     → 同时 AuditIssueHandler 回调自动落盘到 audit_issues.jsonl
 */
public class VulnclawBridge implements BurpExtension, ExtensionUnloadingHandler {

    static final String VERSION = "1.0.8";
    static final int BRIDGE_PORT = 18181;
    static final long MAX_FILE_BYTES = 25L * 1024 * 1024;
    private static final Instant STARTED_AT = Instant.now();
    private final Set<String> auditSeen = ConcurrentHashMap.newKeySet();
    private final Set<String> scanSeen = ConcurrentHashMap.newKeySet();

    private static MontoyaApi apiRef;
    private static Logging staticLog;
    private Logging log;
    private JsonlAppender issueAppender;
    private JsonlAppender historyAppender;
    private ScheduledExecutorService heartbeat;
    private MiniHttpServer httpServer;
    private volatile long auditCount;
    private volatile long historyCount;
    private volatile String lastScanSnapshots = "[]";
    private Path bridgeDir;

    @Override public Set<EnhancedCapability> enhancedCapabilities() { return Set.of(); }

    @Override
    public void initialize(MontoyaApi api) {
        apiRef = api; staticLog = api.logging(); this.log = staticLog;
        this.bridgeDir = resolveBridgeDir();
        try { Files.createDirectories(bridgeDir); }
        catch (IOException e) {
            log.logToError("[VulnclawBridge] 无法创建输出目录 " + bridgeDir + ": " + e);
            return;
        }
        issueAppender = new JsonlAppender(bridgeDir.resolve("audit_issues.jsonl"));
        historyAppender = new JsonlAppender(bridgeDir.resolve("proxy_history.jsonl"));
        auditCount = 0L; historyCount = 0L;

        Registration r1 = api.scanner().registerAuditIssueHandler(new AuditIssueHandler() {
            @Override public void handleNewAuditIssue(AuditIssue issue) { tryWriteAudit(issue, "AuditIssueHandler"); }
        });
        Registration r2 = api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
                try { historyAppender.append(renderHistory(response)); historyCount++; }
                catch (Throwable t) {
                    StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
                    log.logToError("[VulnclawBridge] 写 history 失败: " + t + " -> " + sw);
                }
                return ProxyResponseReceivedAction.continueWith(response);
            }
            @Override public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
                return ProxyResponseToBeSentAction.continueWith(response);
            }
        });
        boolean regOk = r1.isRegistered() && r2.isRegistered();

        // ========== 启动 mini HTTP server (纯 Socket，零依赖) ==========
        try {
            httpServer = new MiniHttpServer("127.0.0.1", BRIDGE_PORT);
            httpServer.addContext("/vulnclaw/scan", this::handleScan);
            httpServer.addContext("/vulnclaw/status", this::handleStatus);
            httpServer.addContext("/vulnclaw/ping", (exc) -> {
                writeJson(exc, 200, "{\"ok\":true,\"version\":\"" + VERSION + "\",\"audit_written\":" + auditCount + ",\"history_written\":" + historyCount + "}");
            });
            httpServer.start();
            log.logToOutput("[VulnclawBridge] mini HTTP server listening on 127.0.0.1:" + BRIDGE_PORT);
        } catch (Throwable t) {
            StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
            log.logToError("[VulnclawBridge] HTTP server 启动失败: " + t + " -> " + sw);
        }

        writeStatusNow(bridgeDir, regOk);

        final Path dirF = bridgeDir; final boolean regF = regOk;
        final long[] counter = {0L};
        heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "vulnclaw-bridge-heartbeat"); t.setDaemon(true); return t;
        });
        heartbeat.scheduleAtFixedRate(() -> {
            try {
                counter[0]++;
                writeStatusNow(dirF, regF);
            } catch (Throwable ignored) {}
        }, 2, 5, TimeUnit.SECONDS);

        // JSON 自检
        try {
            StringBuilder jt = new StringBuilder(); boolean f1 = true;
            f1 = headersObj(jt, f1, "request_headers", List.of());
            headersObj(jt, f1, "X-\"Quoted\"-Key", List.of());
            String sample = "{" + jt + "}";
            log.logToOutput("[VulnclawBridge] JSON 自检样本: " + sample);
            if (sample.contains("\"\"request_headers\"\"")) throw new AssertionError("三引号 bug: " + sample);
        } catch (Throwable ex) {
            StringWriter sw = new StringWriter(); ex.printStackTrace(new PrintWriter(sw));
            log.logToError("[VulnclawBridge] JSON 自检失败: " + ex + " -> " + sw);
        }

        log.logToOutput("[VulnclawBridge] v" + VERSION + " 已加载，输出目录: " + bridgeDir
                + " issues=" + r1.isRegistered() + " history=" + r2.isRegistered()
                + " http_port=" + BRIDGE_PORT + " writable=" + Files.isWritable(bridgeDir));
    }

    /** Burp 卸载扩展时回调 —— 释放 18181 端口、停心跳、关文件句柄，避免 BindException */
    @Override
    public void extensionUnloaded() {
        try {
            if (httpServer != null) httpServer.stop();
            if (heartbeat != null) heartbeat.shutdownNow();
            if (issueAppender != null) issueAppender.closeQuietly();
            if (historyAppender != null) historyAppender.closeQuietly();
            if (staticLog != null) staticLog.logToOutput("[VulnclawBridge] extensionUnloaded: 端口 " + BRIDGE_PORT + " 已释放");
        } catch (Throwable ignored) {}
    }

    /** 兼容旧调用路径 */
    public void close() {
        extensionUnloaded();
    }

    // ========== HTTP handlers (MiniExchange 版，纯 Socket) ==========

    void handleScan(MiniExchange exc) {
        String method = exc.getMethod();
        try {
            if (!"POST".equalsIgnoreCase(method)) {
                writeJson(exc, 405, "{\"error\":\"POST only\"}"); return;
            }
            String body = new String(exc.getRequestBody(), StandardCharsets.UTF_8).trim();
            Map<String, String> params = parseJsonBody(body);
            String urlsRaw = params.getOrDefault("urls", params.getOrDefault("url", ""));
            int timeout = parseInt(params.get("timeout_s"), 300);
            boolean wait = !"false".equalsIgnoreCase(params.get("wait"));
            if (urlsRaw.isBlank()) { writeJson(exc, 400, "{\"error\":\"urls[] or url required\"}"); return; }

            // 解析 URL 列表
            List<String> urls = new ArrayList<>();
            if (urlsRaw.startsWith("[")) {
                // 简单 JSON array 解析（避免引入 Jackson/Gson）
                for (String part : urlsRaw.substring(1, urlsRaw.length() - 1).split(",")) {
                    String cleaned = part.trim();
                    if (cleaned.startsWith("\"")) cleaned = cleaned.substring(1);
                    if (cleaned.endsWith("\"")) cleaned = cleaned.substring(0, cleaned.length() - 1);
                    if (!cleaned.isBlank()) urls.add(cleaned);
                }
            } else {
                urls.add(urlsRaw);
            }
            if (urls.isEmpty()) { writeJson(exc, 400, "{\"error\":\"no urls\"}"); return; }

            log.logToOutput("[VulnclawBridge] SCAN request urls=" + urls + " timeout=" + timeout + " wait=" + wait);

            // 先回 202 ACCEPTED（避免 HTTP client 超时），然后启动扫描线程
            writeJson(exc, 202, "{\"status\":\"accepted\",\"urls_count\":" + urls.size() + "}");

            // 启动扫描
            for (String url : urls) {
                startMontoyaScan(url, timeout, wait);
            }
        } catch (Throwable t) {
            StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
            log.logToError("[VulnclawBridge] handleScan 异常: " + t + " -> " + sw);
            try { writeJson(exc, 500, "{\"error\":\"" + escape(t.toString()) + "\"}"); } catch (IOException ignored) {}
        }
    }

    void handleStatus(MiniExchange exc) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"version\":\"").append(VERSION)
                    .append("\",\"audit_written\":").append(auditCount)
                    .append(",\"history_written\":").append(historyCount)
                    .append(",\"last_heartbeat\":");
            appendJsonString(sb, Instant.now().toString());
            sb.append(",\"scans_seen\":").append(scanSeen.size())
                    .append("}");
            writeJson(exc, 200, sb.toString());
        } catch (Throwable ignored) {}
    }

    /**
     * 用 Montoya API 启动主动扫描。这是关键方法 —— 走 Montoya pipeline 所以 handler 100% 触发。
     */
    void startMontoyaScan(String url, int timeoutSec, boolean wait) {
        if (apiRef == null) { log.logToError("[VulnclawBridge] apiRef 为 null"); return; }
        String scanKey = url + "@" + System.currentTimeMillis();
        if (!scanSeen.add(scanKey)) { log.logToOutput("[VulnclawBridge] 跳过重复 scan: " + url); return; }
        new Thread(() -> {
            try {
                if (url == null || url.isBlank()) return;
                HttpRequest hr = HttpRequest.httpRequestFromUrl(url);
                if (hr == null) { log.logToError("[VulnclawBridge] httpRequestFromUrl 返回 null: " + url); return; }
                log.logToOutput("[VulnclawBridge] 构建 AuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS");
                AuditConfiguration conf = AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
                log.logToOutput("[VulnclawBridge] startAudit(" + url + ") ...");
                Audit audit = apiRef.scanner().startAudit(conf);
                log.logToOutput("[VulnclawBridge] audit started, adding request ...");
                audit.addRequest(hr);
                log.logToOutput("[VulnclawBridge] audit.addRequest done, statusMessage=" + audit.statusMessage());

                if (wait) {
                    // 等待扫描完成（轮询 requestCount / issues）
                    long startMs = System.currentTimeMillis();
                    int lastRequestCount = 0;
                    int stableRounds = 0;
                    log.logToOutput("[VulnclawBridge] 开始轮询 audit, timeout=" + timeoutSec + "s");
                    while (System.currentTimeMillis() - startMs < timeoutSec * 1000L) {
                        try {
                            int reqC = audit.requestCount();
                            int errC = audit.errorCount();
                            int issueC = audit.issues().size();
                            String sm = audit.statusMessage();
                            log.logToOutput("[VulnclawBridge] audit heartbeat req=" + reqC + " err=" + errC + " issues=" + issueC + " status=" + sm);
                            if (reqC > 0 && reqC == lastRequestCount) {
                                stableRounds++;
                                if (stableRounds >= 4) {
                                    log.logToOutput("[VulnclawBridge] requestCount 稳定 " + stableRounds + " 轮，判定扫描完成");
                                    break;
                                }
                            } else {
                                stableRounds = 0;
                            }
                            lastRequestCount = reqC;
                            // 如果 statusMessage 含 "completed"/"finished"/"done" 之类关键词
                            String smlc = sm.toLowerCase();
                            if (smlc.contains("completed") || smlc.contains("finished")
                                    || smlc.contains("done") || smlc.contains("complete")) {
                                log.logToOutput("[VulnclawBridge] statusMessage 表示完成: " + sm);
                                break;
                            }
                        } catch (Throwable pollT) {
                            log.logToError("[VulnclawBridge] 轮询异常: " + pollT);
                        }
                        Thread.sleep(2000);
                    }

                    // 收尾：把 audit.issues() 里的 issue 也手动写一遍（去重已覆盖）
                    try {
                        List<?> issues = audit.issues();
                        int added = 0;
                        for (Object o : issues) {
                            if (o instanceof AuditIssue ai) {
                                if (tryWriteAudit(ai, "MontoyaAuditObject")) added++;
                            }
                        }
                        log.logToOutput("[VulnclawBridge] 扫描结束，从 Audit 对象直接采集 " + added + " 条（handler 同步已写入 " + auditCount + " 条）");
                    } catch (Throwable t) {
                        log.logToError("[VulnclawBridge] audit.issues() 调用失败: " + t);
                    }
                    try { audit.delete(); } catch (Throwable ignored) {}
                }
            } catch (Throwable t) {
                StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
                log.logToError("[VulnclawBridge] startMontoyaScan 异常: " + t + " -> " + sw);
            }
        }, "vulnclaw-bridge-scan-" + url.substring(0, Math.min(60, url.length()))).start();
    }

    // ========== status ==========

    void writeStatusNow(Path dir, boolean registered) {
        try (BufferedWriter w = Files.newBufferedWriter(dir.resolve("status.json"),
                StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            StringBuilder sb = new StringBuilder(256); sb.append('{');
            boolean f = true;
            // version (string) → put 使用逗号前置
            f = put(sb, f, "version", VERSION);
            // registered (bool)
            if (!f) sb.append(','); f = false;
            appendJsonString(sb, "registered"); sb.append(':').append(registered);
            // started (string)
            f = put(sb, f, "started", STARTED_AT.toString());
            // last_heartbeat (string)
            f = put(sb, f, "last_heartbeat", Instant.now().toString());
            // audit_issues_written (number)
            if (!f) sb.append(','); f = false;
            appendJsonString(sb, "audit_issues_written"); sb.append(':').append(auditCount);
            // proxy_events_written (number)
            if (!f) sb.append(','); f = false;
            appendJsonString(sb, "proxy_events_written"); sb.append(':').append(historyCount);
            // bridge_port (number)
            if (!f) sb.append(','); f = false;
            appendJsonString(sb, "bridge_port"); sb.append(':').append(BRIDGE_PORT);
            // scan_snapshots (raw JSON 数组)
            if (!f) sb.append(','); f = false;
            appendJsonString(sb, "scan_snapshots"); sb.append(':')
                    .append(lastScanSnapshots.isEmpty() ? "[]" : lastScanSnapshots);
            sb.append('}'); w.write(sb.toString());
        } catch (Exception e) { if (log != null) log.logToError("[VulnclawBridge] 写 status 失败: " + e); }
    }

    // ========== audit write ==========

    boolean tryWriteAudit(AuditIssue issue, String sourceTag) {
        if (issue == null) return false;
        String ti = "";
        try { AuditIssueDefinition d = issue.definition(); if (d != null) ti = String.valueOf(d.typeIndex()); }
        catch (Throwable ignored) {}
        String key = ti + "|" + nvl(issue.name()) + "|" + nvl(issue.baseUrl())
                + "|" + String.valueOf(issue.severity()) + "|" + String.valueOf(issue.confidence());
        if (!auditSeen.add(key)) return false;
        try {
            issueAppender.append(renderIssue(issue)); auditCount++;
            if (log != null) log.logToOutput("[VulnclawBridge][" + sourceTag + "] issue 写入: "
                    + issue.name() + " sev=" + issue.severity());
            return true;
        } catch (Throwable t) {
            StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
            if (log != null) log.logToError("[VulnclawBridge] 写 issue 失败: " + t + " -> " + sw);
            return false;
        }
    }
    static String nvl(String s) { return s == null ? "" : s; }

    // ========== 渲染 ==========

    String renderIssue(AuditIssue issue) {
        StringBuilder sb = new StringBuilder(1024); sb.append('{'); boolean f = true;
        f = put(sb, f, "ts", Instant.now().toString());
        f = put(sb, f, "name", issue.name());
        f = put(sb, f, "severity", String.valueOf(issue.severity()));
        f = put(sb, f, "confidence", String.valueOf(issue.confidence()));
        f = put(sb, f, "base_url", issue.baseUrl());
        f = put(sb, f, "detail", truncate(issue.detail(), 4000));
        f = put(sb, f, "remediation", truncate(issue.remediation(), 4000));
        try {
            AuditIssueDefinition def = issue.definition();
            if (def != null) {
                f = put(sb, f, "issue_background", truncate(def.background(), 4000));
                f = put(sb, f, "type_index", String.valueOf(def.typeIndex()));
            }
        } catch (Throwable ignored) {}
        try {
            List<? extends HttpRequestResponse> rrs = issue.requestResponses();
            if (rrs != null && !rrs.isEmpty()) {
                if (!f) sb.append(','); f = false;
                appendJsonString(sb, "evidence"); sb.append(":[");
                boolean first = true; int n = 0;
                for (HttpRequestResponse rr : rrs) {
                    if (n++ >= 3) break;
                    if (rr == null) continue;
                    if (!first) sb.append(','); first = false;
                    boolean ff = true; sb.append('{');
                    ff = put(sb, ff, "url", safeStr(rr::url));
                    ff = put(sb, ff, "method", safeStr(() -> rr.request() == null ? "" : rr.request().method()));
                    ff = put(sb, ff, "status", safeStr(() -> rr.hasResponse()
                            ? String.valueOf(rr.response().statusCode()) : ""));
                    put(sb, ff, "request", truncate(safeStr(() -> rr.request() == null
                            ? "" : rr.request().toString()), 4000));
                    sb.append('}');
                }
                sb.append(']');
            }
        } catch (Throwable ignored) {}
        sb.append('}'); return sb.toString();
    }

    String renderHistory(InterceptedResponse response) {
        HttpRequest captured; try { captured = response.initiatingRequest(); } catch (Throwable t) { captured = null; }
        final HttpRequest req = captured;
        StringBuilder sb = new StringBuilder(2048); sb.append('{'); boolean f = true;
        f = put(sb, f, "ts", Instant.now().toString());
        f = put(sb, f, "message_id", String.valueOf(response.messageId()));
        f = put(sb, f, "status", String.valueOf(response.statusCode()));
        if (req != null) {
            f = put(sb, f, "url", safeStr(req::url));
            f = put(sb, f, "method", safeStr(req::method));
            f = put(sb, f, "host", safeStr(() -> svcField(req, "host")));
            f = put(sb, f, "port", safeStr(() -> svcField(req, "port")));
            f = put(sb, f, "secure", safeStr(() -> svcField(req, "secure")));
            f = headersObj(sb, f, "request_headers", req.headers());
            f = put(sb, f, "request_body", truncate(safeStr(req::bodyToString), 4096));
            f = extractCookieKeys(sb, f, req.headers());
        }
        f = headersObj(sb, f, "response_headers", response.headers());
        f = extractSetCookieKeys(sb, f, response.headers());
        sb.append('}'); return sb.toString();
    }

    static String svcField(HttpRequest req, String field) {
        try {
            if (req.httpService() == null) return "";
            switch (field) {
                case "host": return req.httpService().host();
                case "port": return String.valueOf(req.httpService().port());
                case "secure": return String.valueOf(req.httpService().secure());
            }
        } catch (Throwable ignored) {}
        return "";
    }

    boolean headersObj(StringBuilder sb, boolean first, String key, List<? extends HttpHeader> hs) {
        if (!first) sb.append(','); sb.append('"'); escapeChars(sb, key); sb.append("\":{");
        try {
            boolean hf = true;
            for (HttpHeader h : hs) {
                if (!hf) sb.append(','); hf = false;
                appendJsonString(sb, h.name()); sb.append(':'); appendJsonString(sb, h.value());
            }
        } catch (Throwable ignored) {}
        sb.append('}'); return false;
    }

    boolean extractCookieKeys(StringBuilder sb, boolean first, List<? extends HttpHeader> reqHeaders) {
        try {
            StringBuilder cookieSb = new StringBuilder();
            for (HttpHeader h : reqHeaders) {
                if ("Cookie".equalsIgnoreCase(h.name())) {
                    if (cookieSb.length() > 0) cookieSb.append(',');
                    String v = h.value();
                    for (String kv : v.split(";")) {
                        int eq = kv.indexOf('=');
                        String k = (eq >= 0 ? kv.substring(0, eq) : kv).trim();
                        if (!k.isEmpty()) { if (cookieSb.length() > 0) cookieSb.append(','); cookieSb.append(k); }
                    }
                }
            }
            if (cookieSb.length() > 0) {
                if (!first) sb.append(','); first = false;
                appendJsonString(sb, "request_cookie_keys"); sb.append(':'); appendJsonString(sb, cookieSb.toString());
            }
        } catch (Throwable ignored) {}
        return first;
    }

    boolean extractSetCookieKeys(StringBuilder sb, boolean first, List<? extends HttpHeader> respHeaders) {
        List<String> names = new ArrayList<>();
        try {
            for (HttpHeader h : respHeaders) {
                if ("Set-Cookie".equalsIgnoreCase(h.name())) {
                    String v = h.value(); int eq = v.indexOf('=');
                    if (eq > 0) { String name = v.substring(0, eq).trim();
                        if (!name.isEmpty() && !name.equalsIgnoreCase("deleted")) names.add(name); }
                }
            }
            if (!names.isEmpty()) {
                if (!first) sb.append(','); first = false;
                appendJsonString(sb, "response_set_cookie_keys"); sb.append(':'); sb.append('[');
                for (int i = 0; i < names.size(); i++) {
                    if (i > 0) sb.append(','); appendJsonString(sb, names.get(i));
                }
                sb.append(']');
            }
        } catch (Throwable ignored) {}
        return first;
    }

    // ========== HTTP helpers ==========

    static void writeJson(MiniExchange exc, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        HashMap<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json; charset=utf-8");
        headers.put("Content-Length", String.valueOf(bytes.length));
        headers.put("Connection", "close");
        exc.sendResponse(code, bytes, headers);
    }
    static Map<String, String> parseJsonBody(String body) {
        Map<String, String> map = new ConcurrentHashMap<>();
        if (body == null || body.isBlank()) return map;
        // 极简 JSON object parser，只处理 {"key":"value"} 和 {"key":[...] } 混合
        String s = body.trim();
        if (!s.startsWith("{") || !s.endsWith("}")) return map;
        s = s.substring(1, s.length() - 1);
        int i = 0;
        while (i < s.length()) {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
            if (i >= s.length()) break;
            if (s.charAt(i) != '"') { i++; continue; }
            int j = i + 1;
            while (j < s.length() && s.charAt(j) != '"') { if (s.charAt(j) == '\\') j++; j++; }
            String key = unescape(s.substring(i + 1, j));
            i = j + 1;
            while (i < s.length() && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ':')) i++;
            if (i >= s.length()) break;
            String val;
            if (s.charAt(i) == '"') {
                int k = i + 1;
                while (k < s.length() && s.charAt(k) != '"') { if (s.charAt(k) == '\\') k++; k++; }
                val = unescape(s.substring(i + 1, k));
                i = k + 1;
            } else if (s.charAt(i) == '[' || s.charAt(i) == '{') {
                // skip to matching close
                char open = s.charAt(i);
                char close = open == '[' ? ']' : '}';
                int depth = 1; int k = i + 1;
                while (k < s.length() && depth > 0) {
                    if (s.charAt(k) == open && s.charAt(k - 1) != '\\') depth++;
                    else if (s.charAt(k) == close) depth--;
                    k++;
                }
                val = s.substring(i, k); i = k;
            } else {
                int k = i;
                while (k < s.length() && s.charAt(k) != ',' && s.charAt(k) != '}') k++;
                val = s.substring(i, k).trim(); i = k;
            }
            map.put(key, val);
            while (i < s.length() && (Character.isWhitespace(s.charAt(i)) || s.charAt(i) == ',')) i++;
        }
        return map;
    }
    static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case 'n' -> sb.append('\n'); case 'r' -> sb.append('\r'); case 't' -> sb.append('\t');
                    case '"' -> sb.append('"'); case '\\' -> sb.append('\\');
                    default -> sb.append(n);
                }
            } else sb.append(c);
        }
        return sb.toString();
    }
    static String escape(String s) {
        return s == null ? "" : s.replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
    static int parseInt(String s, int def) {
        try { return Integer.parseInt(s); } catch (Throwable ignored) { return def; }
    }

    // ========== 工具 ==========

    interface StrSupplier { String get(); }
    static String safeStr(StrSupplier s) { try { String v = s.get(); return v == null ? "" : v; } catch (Throwable t) { return ""; } }
    static boolean put(StringBuilder sb, boolean first, String key, String value) {
        if (!first) sb.append(','); appendJsonString(sb, key); sb.append(':'); appendJsonString(sb, value == null ? "" : value); return false;
    }
    static String truncate(String s, int max) {
        if (s == null) return ""; s = s.replace("\r", "").replace("\n", "\\n");
        return s.length() <= max ? s : s.substring(0, max) + "...<truncated>";
    }
    static Path resolveBridgeDir() {
        String d = System.getProperty("vulnclaw.bridge.dir");
        if (d == null || d.isBlank()) d = System.getenv("VULNCLAW_BRIDGE_DIR");
        if (d == null || d.isBlank()) d = Paths.get(System.getProperty("user.home"), "Desktop", "pentest_platform", "_runtime_cache", "burp_bridge").toString();
        return Paths.get(d);
    }
    static void appendJsonString(StringBuilder sb, String s) { sb.append('"'); escapeChars(sb, s); sb.append('"'); }
    static void escapeChars(StringBuilder sb, String s) {
        if (s == null) return;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"'  -> sb.append("\\\""); case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n"); case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t"); case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> { if (c < 0x20) sb.append(String.format("\\u%04x", (int) c)); else sb.append(c); }
            }
        }
    }

    // ========== 追加器 ==========
    static final class JsonlAppender {
        private final Path file; private BufferedWriter writer;
        JsonlAppender(Path file) { this.file = file; }
        synchronized void append(String line) throws IOException {
            if (Files.exists(file) && Files.size(file) > MAX_FILE_BYTES) {
                closeQuietly();
                try { Files.move(file, file.resolveSibling(file.getFileName() + ".old"), java.nio.file.StandardCopyOption.REPLACE_EXISTING); }
                catch (IOException ignored) {}
            }
            if (writer == null) writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            writer.write(line); writer.write('\n'); writer.flush();
        }
        void closeQuietly() { if (writer != null) { try { writer.close(); } catch (IOException ignored) {} writer = null; } }
    }

    // ========== 纯 Socket 迷你 HTTP 服务器（零依赖，绕开 jdk.httpserver 模块缺失）==========

    @FunctionalInterface
    interface MiniHandler { void handle(MiniExchange exc) throws IOException; }

    static final class MiniExchange {
        private final Socket sock;
        private final String method;
        private final String path;
        private final HashMap<String, String> reqHeaders;
        private final byte[] reqBody;
        private boolean responded;

        MiniExchange(Socket s, String m, String p, HashMap<String, String> rh, byte[] rb) {
            this.sock = s; this.method = m; this.path = p; this.reqHeaders = rh; this.reqBody = rb; this.responded = false;
        }
        String getMethod() { return method; }
        String getPath() { return path; }
        byte[] getRequestBody() { return reqBody; }
        HashMap<String, String> getRequestHeaders() { return reqHeaders; }

        void sendResponse(int code, byte[] body, HashMap<String, String> extraHeaders) throws IOException {
            if (responded) return;
            responded = true;
            String reason = switch (code) {
                case 200 -> "OK"; case 202 -> "Accepted";
                case 400 -> "Bad Request"; case 404 -> "Not Found";
                case 405 -> "Method Not Allowed"; case 500 -> "Internal Server Error";
                default -> "Status";
            };
            OutputStream os = sock.getOutputStream();
            StringBuilder head = new StringBuilder(256);
            head.append("HTTP/1.1 ").append(code).append(' ').append(reason).append("\r\n");
            HashMap<String, String> hdrs = new HashMap<>();
            hdrs.put("Server", "VulnclawBridge/" + VERSION);
            hdrs.put("Date", java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC)
                    .format(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME));
            if (body != null && body.length > 0 && !hdrs.containsKey("Content-Length")) {
                hdrs.put("Content-Length", String.valueOf(body.length));
            }
            if (extraHeaders != null) hdrs.putAll(extraHeaders);
            if (code >= 400 && body == null) { byte[] eb = (reason + "\r\n").getBytes(StandardCharsets.UTF_8); body = eb; hdrs.put("Content-Length", String.valueOf(eb.length)); }
            // 禁止 chunked 以简化客户端解析
            hdrs.remove("Transfer-Encoding");
            for (Map.Entry<String, String> e : hdrs.entrySet()) {
                head.append(e.getKey()).append(": ").append(e.getValue()).append("\r\n");
            }
            head.append("\r\n");
            os.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
            if (body != null && body.length > 0) os.write(body);
            os.flush();
        }
    }

    static final class MiniHttpServer {
        private final String host;
        private final int port;
        private final HashMap<String, MiniHandler> contexts = new HashMap<>();
        private ServerSocket serverSocket;
        private Thread acceptThread;
        private volatile boolean running;

        MiniHttpServer(String host, int port) { this.host = host; this.port = port; }

        void addContext(String path, MiniHandler h) { contexts.put(path, h); }

        void start() throws IOException {
            serverSocket = new ServerSocket(port, 32, InetAddress.getByName(host));
            running = true;
            acceptThread = new Thread(() -> {
                while (running && !Thread.currentThread().isInterrupted()) {
                    try {
                        Socket sock = serverSocket.accept();
                        sock.setSoTimeout(30000);
                        sock.setTcpNoDelay(true);
                        new Thread(() -> handleSocket(sock), "vulnclaw-bridge-http-worker").start();
                    } catch (java.net.SocketException closed) {
                        if (!running) break;
                    } catch (IOException e) {
                        if (!running) break;
                    }
                }
            }, "vulnclaw-bridge-http-accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
        }

        void stop() {
            running = false;
            if (serverSocket != null) { try { serverSocket.close(); } catch (IOException ignored) {} }
            if (acceptThread != null) { acceptThread.interrupt(); }
        }

        private void handleSocket(Socket sock) {
            try {
                InputStream is = sock.getInputStream();
                // ---- parse request line ----
                ByteArrayOutputStream lineBuf = new ByteArrayOutputStream(256);
                String method = null, path = null;
                int crlfState = 0, b;
                while (crlfState < 2 && (b = is.read()) >= 0) {
                    if (b == '\r') { crlfState = 1; continue; }
                    if (b == '\n' && crlfState == 1) { crlfState = 2; break; }
                    crlfState = 0;
                    lineBuf.write(b);
                }
                if (crlfState < 2) return;
                String reqLine = lineBuf.toString("US-ASCII");
                int sp1 = reqLine.indexOf(' ');
                if (sp1 <= 0) return;
                method = reqLine.substring(0, sp1);
                int sp2 = reqLine.indexOf(' ', sp1 + 1);
                if (sp2 <= sp1) return;
                path = reqLine.substring(sp1 + 1, sp2);

                // ---- parse headers ----
                HashMap<String, String> headers = new HashMap<>();
                while (true) {
                    ByteArrayOutputStream hlBuf = new ByteArrayOutputStream(256);
                    int hlState = 0;
                    while (hlState < 2 && (b = is.read()) >= 0) {
                        if (b == '\r') { hlState = 1; continue; }
                        if (b == '\n' && hlState == 1) { hlState = 2; break; }
                        hlState = 0;
                        hlBuf.write(b);
                    }
                    if (hlState < 2) return;
                    String line = hlBuf.toString("US-ASCII");
                    if (line.isEmpty()) break; // end of headers
                    int colon = line.indexOf(':');
                    if (colon > 0) {
                        String k = line.substring(0, colon).trim().toLowerCase();
                        String v = line.substring(colon + 1).trim();
                        headers.put(k, v);
                    }
                }

                // ---- read body ----
                byte[] body = new byte[0];
                int contentLen = -1;
                try {
                    String cl = headers.get("content-length");
                    if (cl != null) contentLen = Integer.parseInt(cl);
                } catch (NumberFormatException ignored) {}
                if (contentLen > 0) {
                    int max = Math.min(contentLen, 16 * 1024 * 1024); // 16 MiB cap
                    body = new byte[max];
                    int off = 0, toRead = max;
                    while (toRead > 0) {
                        int n = is.read(body, off, toRead);
                        if (n < 0) break;
                        off += n; toRead -= n;
                    }
                    if (off < body.length) { byte[] t = new byte[off]; System.arraycopy(body, 0, t, 0, off); body = t; }
                } else if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
                    ByteArrayOutputStream chunkBuf = new ByteArrayOutputStream(65536);
                    while (true) {
                        // read size line
                        ByteArrayOutputStream szBuf = new ByteArrayOutputStream(16);
                        int szState = 0;
                        while (szState < 2 && (b = is.read()) >= 0) {
                            if (b == '\r') { szState = 1; continue; }
                            if (b == '\n' && szState == 1) { szState = 2; break; }
                            szState = 0;
                            szBuf.write(b);
                        }
                        if (szState < 2) break;
                        String szLine = szBuf.toString("US-ASCII");
                        int semi = szLine.indexOf(';');
                        if (semi >= 0) szLine = szLine.substring(0, semi);
                        int chunkSize;
                        try { chunkSize = Integer.parseInt(szLine.trim(), 16); }
                        catch (NumberFormatException nfe) { break; }
                        if (chunkSize == 0) { break; }
                        int left = chunkSize;
                        byte[] cb = new byte[4096];
                        while (left > 0) {
                            int nr = is.read(cb, 0, Math.min(cb.length, left));
                            if (nr < 0) break;
                            chunkBuf.write(cb, 0, nr); left -= nr;
                        }
                        // trailing \r\n
                        is.read(); is.read();
                    }
                    body = chunkBuf.toByteArray();
                }

                MiniExchange exc = new MiniExchange(sock, method, path, headers, body);
                MiniHandler h = matchPath(path);
                if (h == null) {
                    exc.sendResponse(404, null, null);
                } else {
                    try { h.handle(exc); }
                    catch (Throwable t) {
                        try { exc.sendResponse(500, ("Handler error: " + t).getBytes(StandardCharsets.UTF_8), null); }
                        catch (IOException ignored) {}
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                try { sock.close(); } catch (IOException ignored) {}
            }
        }

        private MiniHandler matchPath(String p) {
            MiniHandler h = contexts.get(p);
            if (h != null) return h;
            // fallback: 前缀最长匹配
            String best = null;
            for (String prefix : contexts.keySet()) {
                if (p.startsWith(prefix) && (best == null || prefix.length() > best.length())) best = prefix;
            }
            return best == null ? null : contexts.get(best);
        }
    }
}
