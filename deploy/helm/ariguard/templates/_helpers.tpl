{{- define "ariguard.tag" -}}
{{- .Values.image.tag | default .Chart.AppVersion -}}
{{- end -}}

{{- define "ariguard.image" -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .name (include "ariguard.tag" .root) -}}
{{- end -}}

{{- define "ariguard.labels" -}}
app.kubernetes.io/part-of: ariguard
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "ariguard.sinkUrl" -}}
{{- if .Values.agent.sinkUrl -}}
{{- .Values.agent.sinkUrl -}}
{{- else if .Values.console.enabled -}}
{{- printf "http://ariguard-console-backend.%s.svc:8080" .Values.namespace -}}
{{- end -}}
{{- end -}}
