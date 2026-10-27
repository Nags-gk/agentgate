#!/usr/bin/env bash
# Deploy AgentGate to Cloud Run from Google Cloud Shell (already signed in).
#
#   git clone https://github.com/Nags-gk/agentgate && cd agentgate
#   PROJECT=project-security-512220 bash deploy/cloudrun.sh
#   NEW_DB_URL=1 PROJECT=... bash deploy/cloudrun.sh    # replace a stored connection string
#
# Asks once for the CockroachDB Cloud connection string (input hidden) and stores it, a
# freshly generated vault key and, optionally, a Gemini key in Secret Manager. Nothing
# secret is written to disk or to the repo.
set -euo pipefail

PROJECT="${PROJECT:?set PROJECT to your Google Cloud project id}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-agentgate}"
SA="agentgate-run@${PROJECT}.iam.gserviceaccount.com"

gcloud config set project "$PROJECT" >/dev/null
echo "Enabling APIs (first run takes a minute)..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com >/dev/null

secret() { # name, value-from-stdin
  if gcloud secrets describe "$1" >/dev/null 2>&1; then
    gcloud secrets versions add "$1" --data-file=- >/dev/null
  else
    gcloud secrets create "$1" --replication-policy=automatic --data-file=- >/dev/null
  fi
}

if [[ -n "${NEW_DB_URL:-}" ]] || ! gcloud secrets describe agentgate-database-url >/dev/null 2>&1; then
  read -rsp "CockroachDB Cloud connection string (postgresql://...): " DBURL; echo
  [[ "$DBURL" == postgresql://* ]] || { echo "That does not look like a connection string."; exit 1; }
  [[ "$DBURL" == *sslmode=* ]] || DBURL="${DBURL}$([[ "$DBURL" == *\?* ]] && echo '&' || echo '?')sslmode=verify-full"
  printf '%s' "$DBURL" | secret agentgate-database-url
  unset DBURL
fi
if ! gcloud secrets describe agentgate-vault-keks >/dev/null 2>&1; then
  printf '1:%s' "$(head -c 32 /dev/urandom | base64)" | secret agentgate-vault-keks
fi
GEMINI_FLAG=()
if gcloud secrets describe agentgate-gemini-key >/dev/null 2>&1; then
  GEMINI_FLAG=(--set-secrets "GEMINI_API_KEY=agentgate-gemini-key:latest")
fi

if ! gcloud iam service-accounts describe "$SA" >/dev/null 2>&1; then
  gcloud iam service-accounts create agentgate-run --display-name "AgentGate on Cloud Run" >/dev/null
fi
for s in agentgate-database-url agentgate-vault-keks agentgate-gemini-key; do
  gcloud secrets describe "$s" >/dev/null 2>&1 && \
    gcloud secrets add-iam-policy-binding "$s" --member "serviceAccount:$SA" --role roles/secretmanager.secretAccessor >/dev/null
done

NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
URL="https://${SERVICE}-${NUMBER}.${REGION}.run.app"

echo "Building and deploying (Cloud Build, about 4 minutes)..."
gcloud run deploy "$SERVICE" --source . --region "$REGION" --service-account "$SA" \
  --allow-unauthenticated --port 8080 --cpu 1 --memory 1Gi \
  --min-instances 0 --max-instances 1 --concurrency 80 --timeout 300 \
  --startup-probe httpGet.path=/health,httpGet.port=8080,initialDelaySeconds=0,periodSeconds=5,timeoutSeconds=3,failureThreshold=60 \
  --set-env-vars "PUBLIC_URL=${URL},DEMO_MODE=true,DB_POOL_SIZE=8" \
  --set-secrets "DATABASE_URL=agentgate-database-url:latest,VAULT_KEKS=agentgate-vault-keks:latest" \
  "${GEMINI_FLAG[@]}"

echo
echo "Deployed: ${URL}"
curl -fsS "${URL}/health" && echo
