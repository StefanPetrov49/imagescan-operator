#!/usr/bin/env bash
# From a fresh clone to a running, warmed-up demo in one command (make demo-setup):
#   kind cluster -> cert-manager -> operator -> demo workloads -> warm-up scan
# Safe to run again: every step skips or updates what already exists.
set -euo pipefail

cd "$(dirname "$0")/.."
CLUSTER=${CLUSTER:-imagescan}
IMG=${IMG:-imagescan-operator:dev}
CERT_MANAGER_VERSION=${CERT_MANAGER_VERSION:-v1.21.1} # same version as the e2e tests
NS=imagescan-operator-system
DEPLOY=deployment/imagescan-operator-controller-manager

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

# wait_done polls an ImageScan until it reaches a final phase and prints that phase.
# Progress dots go to stderr, so they stay visible inside $(...).
wait_done() {
  local phase=""
  for _ in $(seq 1 900); do # up to 30 minutes
    phase=$(kubectl get imagescan "$1" -o jsonpath='{.status.phase}' 2>/dev/null || true)
    case "$phase" in Succeeded | PartiallyFailed | Failed) break ;; esac
    printf '.' >&2
    sleep 2
  done
  echo >&2
  echo "$phase"
}

step "Checking tools"
for tool in docker kind kubectl go make jq curl; do
  command -v "$tool" >/dev/null || {
    echo "missing: $tool" >&2
    exit 1
  }
done
echo "ok"

step "kind cluster '$CLUSTER'"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER"
elif [ "$(docker inspect -f '{{.State.Running}}' "$CLUSTER-control-plane")" != "true" ]; then
  echo "starting the stopped cluster"
  docker start "$CLUSTER-control-plane" >/dev/null
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
until kubectl get nodes >/dev/null 2>&1; do sleep 2; done # API server is still starting
kubectl wait --for=condition=Ready node --all --timeout=3m

step "cert-manager (issues the webhook's TLS certificate)"
if kubectl get deployment cert-manager -n cert-manager >/dev/null 2>&1; then
  echo "already installed"
else
  kubectl apply -f "https://github.com/cert-manager/cert-manager/releases/download/$CERT_MANAGER_VERSION/cert-manager.yaml" >/dev/null
fi
kubectl wait --for=condition=Available deployment --all -n cert-manager --timeout=5m

step "Building and deploying the operator ($IMG)"
make docker-build IMG="$IMG"
kind load docker-image "$IMG" --name "$CLUSTER"
make deploy IMG="$IMG"
kubectl rollout restart "$DEPLOY" -n "$NS" # picks up a rebuilt image with the same tag
kubectl rollout status "$DEPLOY" -n "$NS" --timeout=5m

step "Private registry (optional)"
if [ -n "${DOCKERHUB_USER:-}" ] && [ -n "${DOCKERHUB_TOKEN:-}" ]; then
  # One Secret for Trivy (operator namespace) and one so the kubelet can pull the Pod.
  for ns in "$NS" default; do
    kubectl create secret docker-registry dockerhub-creds -n "$ns" \
      --docker-server=https://index.docker.io/v1/ \
      --docker-username="$DOCKERHUB_USER" --docker-password="$DOCKERHUB_TOKEN" \
      --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  done
  if ! kubectl get pod private-app -n default >/dev/null 2>&1; then
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: private-app
  namespace: default
  labels:
    app: private
spec:
  imagePullSecrets:
    - name: dockerhub-creds
  containers:
    - name: app
      image: ${PRIVATE_IMAGE:-docker.io/petrov4o/imagescan-private:test}
EOF
  fi
  echo "Secret dockerhub-creds and Pod private-app ready"
else
  echo "skipped: set DOCKERHUB_USER, DOCKERHUB_TOKEN (and PRIVATE_IMAGE) to include it"
fi

step "Demo workloads (namespaces production and staging)"
kubectl apply -f demo/00-workloads.yaml
kubectl wait --for=condition=Ready pod --all -n production --timeout=5m
kubectl wait --for=condition=Ready pod --all -n staging --timeout=5m

step "Warm-up scan (the very first one downloads Trivy's databases: up to ~10 minutes)"
kubectl delete imagescan warmup --ignore-not-found >/dev/null
# Right after the operator starts, the webhook may need a few seconds for its certificate.
for attempt in $(seq 1 30); do
  if kubectl create -f demo/warmup.yaml; then break; fi
  [ "$attempt" -lt 30 ] || exit 1
  echo "webhook not ready yet, retrying in 5s"
  sleep 5
done
phase=$(wait_done warmup)
if [ "$phase" != "Succeeded" ]; then
  echo "warm-up scan ended as '${phase:-timeout}':" >&2
  kubectl get imagescan warmup -o jsonpath='{.status}' | jq . >&2
  exit 1
fi

step "Ready"
cat <<EOF
Operator running, demo workloads in place, Trivy cache warm.
  make demo        guided walkthrough: press Enter to run each step
  make demo-clean  delete the kind cluster
EOF
