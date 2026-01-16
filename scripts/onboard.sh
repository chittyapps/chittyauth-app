#!/bin/bash
set -euo pipefail
echo "=== chittyauth-app Onboarding ==="
curl -s -X POST "${GETCHITTY_ENDPOINT:-https://get.chitty.cc/api/onboard}" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"chittyauth-app","organization":"CHITTYAPPS","type":"application","tier":5,"domains":["auth-app.chitty.cc"]}' | jq .
