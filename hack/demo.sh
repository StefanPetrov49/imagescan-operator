#!/usr/bin/env bash
# Guided demo of the ImageScan operator (make demo, after make demo-setup).
# Each step says what it shows, prints the command and waits for Enter before
# running it, so nothing has to be typed or remembered.
set -uo pipefail # no -e: some steps are supposed to fail (rejected requests)

cd "$(dirname "$0")/.."
NS=imagescan-operator-system
SA="system:serviceaccount:$NS:imagescan-operator-controller-manager"
PORT=${PORT:-8080}
API="http://localhost:$PORT"

# title prints a step heading and one line per remaining argument.
title() {
  printf '\n\033[1m== %s ==\033[0m\n' "$1"
  shift
  for line in "$@"; do printf '   %s\n' "$line"; done
}

# run prints a command, waits for Enter, then runs it.
run() {
  printf '\n\033[32m$ %s\033[0m' "$1"
  read -r -s
  echo
  eval "$1"
}

# wait_done polls an ImageScan until it reaches a final phase.
wait_done() {
  local phase=""
  printf 'waiting for %s ' "$1"
  for _ in $(seq 1 600); do # up to 20 minutes
    phase=$(kubectl get imagescan "$1" -o jsonpath='{.status.phase}' 2>/dev/null)
    case "$phase" in Succeeded | PartiallyFailed | Failed) break ;; esac
    printf '.'
    sleep 2
  done
  printf ' %s\n' "${phase:-timed out}"
}

# Start clean, so the demo can be run any number of times.
# Reports from earlier runs stay on the volume, as they should.
kubectl delete imagescan production-web production-web-critical private-no-secret private-with-secret \
  --ignore-not-found >/dev/null

title "1. What is installed" \
  "Cluster-scoped ImageScan CRD, the operator (one Pod: manager + results-server)," \
  "the results PVC, the ClusterIP Service and the validating webhook."
run "kubectl get crd imagescans.security.stefanpetrov.dev"
run "kubectl get deployment,pods,service,pvc -n $NS"
run "kubectl get validatingwebhookconfigurations | grep imagescan"

title "2. The task's scenario: Pods with app=web in namespaces with env=production" \
  "production runs nginx and redis; staging runs alpine with the same app=web label." \
  "The webhook's warning should list 2 images: the namespace selector leaves staging out." \
  "At the end, the finished Jobs are already gone: the operator deletes them."
run "kubectl get pods -A -l app=web -L app"
run "kubectl get namespaces -L env"
run "cat demo/01-production-web.yaml"
run "kubectl create -f demo/01-production-web.yaml"
wait_done production-web
run "kubectl get imagescan production-web -o jsonpath='{.status}' | jq ."
run "kubectl get jobs -n $NS"

title "3. Results over HTTP (ClusterIP Service, reached with port-forward)" \
  "GET /scans: summaries, filter ?image=<prefix>, bonus pagination ?limit=&offset=." \
  "GET /scans/{id}: the full Trivy JSON report of one image."
run "kubectl port-forward -n $NS service/imagescan-operator-scan-results $PORT:80 >/dev/null &"
PF=$!
trap 'kill "$PF" 2>/dev/null' EXIT
until curl -s "$API/healthz" >/dev/null; do sleep 1; done
ID=$(kubectl get imagescan production-web -o jsonpath='{.status.scans[0].id}')
run "curl -s '$API/scans?limit=3' | jq '{total, items: [.items[] | {id, imageScan, image, vulnerabilities}]}'"
run "curl -s $API/scans/$ID | jq '{image: .ArtifactName, first: (.Results[0].Vulnerabilities[0] | {VulnerabilityID, PkgName, Severity})}'"
run "curl -s '$API/scans?image=redis' | jq '{total, images: [.items[].image] | unique}'"
run "curl -s '$API/scans?limit=1&offset=1' | jq '{total, limit, offset, image: .items[0].image}'"
run "curl -s -w ' -> HTTP %{http_code}\n' $API/scans/hello"

title "4. Validation, in three layers" \
  "Webhook: rejects a scan that matches no Pods." \
  "CRD schema: rejects an unknown severity." \
  "CEL rule (self == oldSelf): rejects any change to an existing spec."
run "kubectl create -f demo/02-no-match.yaml"
run "kubectl create -f demo/03-bad-severity.yaml"
run "kubectl patch imagescan production-web --type=merge -p '{\"spec\":{\"minSeverity\":\"HIGH\"}}'"

title "5. Bonus: minimum severity (Trivy's --severity)" \
  "The same targets as step 2, but only CRITICAL findings are kept."
run "kubectl create -f demo/04-critical-only.yaml"
wait_done production-web-critical
run "curl -s '$API/scans?image=nginx&limit=2' | jq '.items[] | {imageScan, minSeverity, vulnerabilities}'"

if kubectl get secret dockerhub-creds -n "$NS" >/dev/null 2>&1 &&
  [ -n "$(kubectl get pods -A -l app=private -o name)" ]; then
  title "6. Bonus: private registry" \
    "Without credentials Trivy gets UNAUTHORIZED; with registrySecretRef the same image succeeds."
  run "kubectl create -f demo/05-private-no-secret.yaml"
  wait_done private-no-secret
  run "kubectl get imagescan private-no-secret -o jsonpath='{.status.scans[0].message}'; echo"
  run "kubectl create -f demo/06-private-with-secret.yaml"
  wait_done private-with-secret
else
  title "6. Bonus: private registry (skipped)" \
    "Needs the dockerhub-creds Secret and a Pod labelled app=private: see the README."
fi

title "7. Least privilege" \
  "The operator may create Jobs only in its own namespace (a Role, not a ClusterRole)."
run "kubectl auth can-i create jobs -n default --as=$SA"
run "kubectl auth can-i create jobs -n $NS --as=$SA"

title "Done" "The reports stay on the PVC after the ImageScans are deleted."
