# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""UI 路线②最小 TUI 客户端（PGEN-EVENT 状态总线消费端）。

纯标准库实现 WebSocket 客户端（无 websockets/rich 依赖），连接 dashboard 的
/ws 端点，实时消费 ScanEvent 结构化事件流并全屏渲染；底部为「桌宠」占位块——
按桌宠决策仅渲染无角色纯色块（皮肤系统由社区投稿，官方不做设计）。

运行：python -m vulnclaw.dashboard.tui_client --host 127.0.0.1 --port 8080
退出：按 q
"""

import argparse
import base64
import json
import os
import shutil
import socket
import struct
import sys
import time

try:  # Windows 控制台按键检测
    import msvcrt

    def _kbhit() -> bool:
        return msvcrt.kbhit()

    def _getch() -> str:
        try:
            return msvcrt.getwch()
        except Exception:  # noqa: BLE001
            return ""
except Exception:  # noqa: BLE001
    def _kbhit() -> bool:
        return False

    def _getch() -> str:
        return ""


class WsClient:
    """极简 WebSocket 客户端：握手 + 帧解析（server->client 不 mask）+ 渲染。"""

    def __init__(self, host: str, port: int, path: str = "/ws") -> None:
        self.host = host
        self.port = port
        self.path = path
        self.sock: socket.socket = None
        self.buf = b""
        self.events: list = []
        self.max_events = 500
        self._stop = False
        self._dirty = True
        self._w, self._h = shutil.get_terminal_size((80, 24))

    # ----------------------------------------------------------
    # 连接与握手
    # ----------------------------------------------------------
    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        self.sock.settimeout(0.2)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        first_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in first_line:
            raise RuntimeError(f"WS 握手失败: {first_line}")

    # ----------------------------------------------------------
    # 帧解析（RFC6455）
    # ----------------------------------------------------------
    def _try_parse(self):
        buf = self.buf
        if len(buf) < 2:
            return None
        b0, b1 = buf[0], buf[1]
        opcode = b0 & 0x0F
        masked = (b1 & 0x80) != 0
        length = b1 & 0x7F
        idx = 2
        if length == 126:
            if len(buf) < idx + 2:
                return None
            length = struct.unpack(">H", buf[idx:idx + 2])[0]
            idx += 2
        elif length == 127:
            if len(buf) < idx + 8:
                return None
            length = struct.unpack(">Q", buf[idx:idx + 8])[0]
            idx += 8
        if masked:
            if len(buf) < idx + 4:
                return None
            mask = buf[idx:idx + 4]
            idx += 4
        else:
            mask = None
        if len(buf) < idx + length:
            return None
        payload = buf[idx:idx + length]
        if mask:
            payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        self.buf = buf[idx + length:]
        return opcode, payload

    def _send_pong(self, payload: bytes) -> None:
        header = struct.pack("!B", 0x80 | 0x0A)  # FIN + pong
        length = len(payload)
        if length < 126:
            header += struct.pack("!B", length)
        elif length < 65536:
            header += struct.pack("!B", 126) + struct.pack(">H", length)
        else:
            header += struct.pack("!B", 127) + struct.pack(">Q", length)
        mask = os.urandom(4)
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
        try:
            self.sock.sendall(header + mask + masked)
        except OSError:
            pass

    # ----------------------------------------------------------
    # 事件处理
    # ----------------------------------------------------------
    def _on_text(self, payload: bytes) -> None:
        try:
            ev = json.loads(payload.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeDecodeError):
            return
        self.events.append(ev)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
        self._dirty = True

    @staticmethod
    def _fmt(ev: dict) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(ev.get("timestamp", 0)))
        etype = ev.get("type", "?")
        d = ev.get("data", {})
        if isinstance(d, dict):
            if etype == "tool_call_log":
                s = f"{d.get('tool')} [{d.get('phase')}]"
            elif etype == "agent_log":
                s = f"supervisor {d.get('phase')} tool={d.get('tool')} streak={d.get('streak')}"
            elif etype == "vector_store_log":
                s = f"{d.get('op')} {d.get('vuln_type') or d.get('query')}"
            elif etype == "status":
                s = "scan status tick"
            else:
                s = str(d)[:60]
        else:
            s = str(d)[:60]
        return f" {ts}  {etype:<16} {s}"

    def _pet(self) -> str:
        # 桌宠决策：官方不做任何设计，仅渲染无角色纯色占位块
        block = "\u2588" * max(8, min(self._w - 30, 24))
        return f" {block}  [chenge companion · skin placeholder]"

    def _render(self) -> None:
        if not self._dirty:
            return
        self._dirty = False
        self._w, self._h = shutil.get_terminal_size((80, 24))
        head = self._h - 3
        lines = ["\x1b[2J\x1b[H"]
        lines.append(f" chenge · scan bus   {self.host}:{self.port}{self.path}   events={len(self.events)}   (q to quit)")
        lines.append("-" * self._w)
        for ev in self.events[-head:]:
            lines.append(self._fmt(ev)[:self._w])
        lines.append("-" * self._w)
        lines.append(self._pet())
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()

    def _check_quit(self) -> None:
        if _kbhit() and _getch().lower() == "q":
            self._stop = True

    # ----------------------------------------------------------
    # 主循环
    # ----------------------------------------------------------
    def run(self) -> None:
        self.connect()
        self._render()
        while not self._stop:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                chunk = b""
            except OSError:
                break
            if chunk:
                self.buf += chunk
                while True:
                    f = self._try_parse()
                    if f is None:
                        break
                    opcode, payload = f
                    if opcode == 1:  # text
                        self._on_text(payload)
                    elif opcode == 8:  # close
                        self._stop = True
                        break
                    elif opcode == 9:  # ping -> pong
                        self._send_pong(payload)
                    # pong: ignore
            self._check_quit()
            self._render()
        try:
            self.sock.close()
        except OSError:
            pass


def main() -> None:
    ap = argparse.ArgumentParser(description="chenge 状态总线 TUI 客户端")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/ws")
    args = ap.parse_args()
    try:
        WsClient(args.host, args.port, args.path).run()
    except (ConnectionRefusedError, RuntimeError) as e:
        sys.stderr.write(f"[TUI] 无法连接状态总线: {e}\n")
        sys.stderr.write("[TUI] 请先启动 dashboard: python -m vulnclaw.dashboard.server --port 8080\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
