#!/bin/sh
set -eu

: "${WEBHOOK_URL:?WEBHOOK_URL is required}"
: "${RAZORPAY_WEBHOOK_SECRET:?RAZORPAY_WEBHOOK_SECRET is required}"

REQUESTS=${REQUESTS:-200}
CONCURRENCY=${CONCURRENCY:-20}
P95_TARGET_MS=${P95_TARGET_MS:-500}
body='{"entity":"event","event":"subscription.updated","payload":{}}'
signature=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$RAZORPAY_WEBHOOK_SECRET" -hex | sed 's/^.* //')
results=$(mktemp)
trap 'rm -f "$results"' EXIT
export body signature WEBHOOK_URL results

start=$(date +%s)
seq 1 "$REQUESTS" | xargs -P "$CONCURRENCY" -I '{}' sh -c '
  result=$(curl --silent --output /dev/null --write-out "%{http_code} %{time_total}" \
    --header "content-type: application/json" \
    --header "x-razorpay-signature: $signature" \
    --header "x-razorpay-event-id: load-$1" \
    --data "$body" "$WEBHOOK_URL")
  status=${result%% *}
  duration=${result#* }
  test "$status" = 200
  printf "%s\n" "$duration" >> "$results"
' _ '{}'
elapsed=$(( $(date +%s) - start ))
samples=$(wc -l < "$results" | tr -d ' ')
test "$samples" = "$REQUESTS"
p95_index=$(( (REQUESTS * 95 + 99) / 100 ))
p95_seconds=$(sort -n "$results" | sed -n "${p95_index}p")
p95_ms=$(awk "BEGIN { printf \"%.3f\", $p95_seconds * 1000 }")
awk "BEGIN { exit !($p95_ms <= $P95_TARGET_MS) }"
printf 'requests=%s concurrency=%s elapsed_seconds=%s p95_ms=%s target_ms=%s\n' \
  "$REQUESTS" "$CONCURRENCY" "$elapsed" "$p95_ms" "$P95_TARGET_MS"
