{{/*
Chart name and fullname.
*/}}
{{- define "cloudsneeker.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cloudsneeker.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "cloudsneeker.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/*
Common labels. Pass a dict with "root" and "component".
*/}}
{{- define "cloudsneeker.labels" -}}
app.kubernetes.io/name: {{ include "cloudsneeker.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end -}}

{{- define "cloudsneeker.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cloudsneeker.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "cloudsneeker.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "cloudsneeker.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "cloudsneeker.secretName" -}}
{{- default (printf "%s-secrets" (include "cloudsneeker.fullname" .)) .Values.existingSecret -}}
{{- end -}}

{{- define "cloudsneeker.image" -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .component .root.Values.image.tag -}}
{{- end -}}

{{/*
Environment shared by the API, worker, and beat pods.
*/}}
{{- define "cloudsneeker.apiEnv" -}}
- name: DJANGO_SETTINGS_MODULE
  value: config.django.production
- name: DJANGO_BIND_ADDRESS
  value: "0.0.0.0"
- name: DJANGO_PORT
  value: {{ .Values.api.port | quote }}
- name: DJANGO_WORKERS
  value: {{ .Values.api.workers | quote }}
- name: DJANGO_DEBUG
  value: "False"
- name: DJANGO_LOGGING_LEVEL
  value: {{ .Values.api.logLevel | quote }}
- name: DJANGO_LOGGING_FORMATTER
  value: ndjson
- name: DJANGO_ALLOWED_HOSTS
  value: {{ printf "%s,localhost,127.0.0.1" .Values.hosts.api | quote }}
- name: DJANGO_ACCESS_TOKEN_LIFETIME
  value: {{ .Values.api.accessTokenLifetime | quote }}
- name: DJANGO_REFRESH_TOKEN_LIFETIME
  value: {{ .Values.api.refreshTokenLifetime | quote }}
- name: DJANGO_MANAGE_DB_PARTITIONS
  value: {{ .Values.api.manageDbPartitions | quote }}
- name: DJANGO_JWT_ISSUER
  value: {{ printf "https://%s" .Values.hosts.api | quote }}
- name: DJANGO_JWT_AUDIENCE
  value: {{ printf "https://%s" .Values.hosts.api | quote }}
- name: DJANGO_UI_BASE_URL
  value: {{ printf "https://%s" .Values.hosts.app | quote }}
- name: DJANGO_TMP_OUTPUT_DIRECTORY
  value: /tmp/prowler_api_output
- name: POSTGRES_HOST
  value: {{ .Values.datastores.postgres.host | quote }}
- name: POSTGRES_PORT
  value: {{ .Values.datastores.postgres.port | quote }}
- name: POSTGRES_DB
  value: {{ .Values.datastores.postgres.db | quote }}
- name: POSTGRES_USER
  value: {{ .Values.datastores.postgres.user | quote }}
- name: POSTGRES_ADMIN_USER
  value: {{ .Values.datastores.postgres.adminUser | quote }}
- name: VALKEY_SCHEME
  value: {{ .Values.datastores.valkey.scheme | quote }}
- name: VALKEY_HOST
  value: {{ .Values.datastores.valkey.host | quote }}
- name: VALKEY_PORT
  value: {{ .Values.datastores.valkey.port | quote }}
- name: VALKEY_DB
  value: {{ .Values.datastores.valkey.db | quote }}
- name: VALKEY_USERNAME
  value: {{ .Values.datastores.valkey.username | quote }}
- name: NEO4J_HOST
  value: {{ .Values.datastores.neo4j.host | quote }}
- name: NEO4J_PORT
  value: {{ .Values.datastores.neo4j.port | quote }}
- name: NEO4J_USER
  value: {{ .Values.datastores.neo4j.user | quote }}
{{- if .Values.brand.docsUrl }}
- name: CLOUDSNEEKER_DOCS_URL
  value: {{ .Values.brand.docsUrl | quote }}
{{- end }}
{{- if .Values.brand.supportUrl }}
- name: CLOUDSNEEKER_SUPPORT_URL
  value: {{ .Values.brand.supportUrl | quote }}
{{- end }}
{{- range $key, $secretKey := dict "POSTGRES_PASSWORD" "postgresPassword" "POSTGRES_ADMIN_PASSWORD" "postgresAdminPassword" "VALKEY_PASSWORD" "valkeyPassword" "NEO4J_PASSWORD" "neo4jPassword" "DJANGO_TOKEN_SIGNING_KEY" "djangoTokenSigningKey" "DJANGO_TOKEN_VERIFYING_KEY" "djangoTokenVerifyingKey" "DJANGO_SECRETS_ENCRYPTION_KEY" "djangoSecretsEncryptionKey" "DJANGO_SENTRY_DSN" "djangoSentryDsn" }}
- name: {{ $key }}
  valueFrom:
    secretKeyRef:
      name: {{ include "cloudsneeker.secretName" $ }}
      key: {{ $secretKey }}
{{- end }}
{{- with .Values.api.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}
