{{/* 公共命名 */}}
{{- define "vulnclaw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "vulnclaw.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "vulnclaw.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* 公共标签（Helm 推荐标签集） */}}
{{- define "vulnclaw.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "vulnclaw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* 镜像引用：tag 为空则回退 Chart.appVersion（避免版本双处维护） */}}
{{- define "vulnclaw.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* 集群内 Redis DSN（覆盖 .env 中的 localhost，语义同 compose） */}}
{{- define "vulnclaw.redisUrl" -}}
redis://{{ include "vulnclaw.fullname" . }}-redis:6379/0
{{- end -}}
