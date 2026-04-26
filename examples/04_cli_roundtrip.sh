#!/usr/bin/env bash
# Example 04 — End-to-end CLI round-trip: input -> audit -> verify.
#
# Demonstrates that clients (and regulators) need only a JSON file and the
# `"${REGAUDIT_FHE:-regaudit-fhe}"` binary; no Python knowledge required.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

cat > /tmp/fairness_input.json <<'JSON'
{
  "y_true":  [1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0],
  "y_pred":  [1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0],
  "group_a": [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
  "group_b": [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
  "threshold": 0.1
}
JSON

echo "==> Schema:"
"${REGAUDIT_FHE:-regaudit-fhe}" audit fairness --schema

echo
echo "==> Run audit:"
"${REGAUDIT_FHE:-regaudit-fhe}" audit fairness -i /tmp/fairness_input.json -o /tmp/fairness_envelope.json
cat /tmp/fairness_envelope.json

echo
echo "==> Verify receipt:"
"${REGAUDIT_FHE:-regaudit-fhe}" verify -i /tmp/fairness_envelope.json
