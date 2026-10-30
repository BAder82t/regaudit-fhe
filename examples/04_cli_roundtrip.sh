#!/usr/bin/env bash
# Example 04 -- End-to-end CLI round-trip: input -> audit -> verify.
#
# Needs only the `regaudit-fhe` command (override with REGAUDIT_FHE=/path/to/regaudit-fhe)
# and runs from any directory. Everything is written to a temporary directory.
#
# `regaudit-fhe audit` signs with an ephemeral key, so its output can only ever verify as
# SELF_SIGNED_ONLY: the file is intact, but nothing says who signed it. `verify` therefore
# exits 1 here, and this script checks that it does. To see a report accepted as TRUSTED
# against a trust store, run examples/strict_verification_quickstart.py.

set -euo pipefail
RF="${REGAUDIT_FHE:-regaudit-fhe}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/regaudit-cli-roundtrip.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/fairness_input.json" <<'JSON'
{
  "y_true":  [1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0],
  "y_pred":  [1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0],
  "group_a": [1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0],
  "group_b": [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1],
  "threshold": 0.1
}
JSON

echo "==> Schema:"
"$RF" audit fairness --schema

echo
echo "==> Run audit:"
"$RF" audit fairness -i "$WORK/fairness_input.json" -o "$WORK/fairness_envelope.json"
head -c 400 "$WORK/fairness_envelope.json"; echo " ..."

echo
echo "==> Verify without a trust store (development check only):"
status=0
"$RF" verify -i "$WORK/fairness_envelope.json" --allow-self-signed > "$WORK/verdict.json" || status=$?
cat "$WORK/verdict.json"
if [ "$status" -ne 1 ] || ! grep -q '"trust_status": "SELF_SIGNED_ONLY"' "$WORK/verdict.json"; then
  echo "unexpected verify result (exit $status)" >&2
  exit 1
fi
echo
echo "==> Exit 1 / SELF_SIGNED_ONLY, as expected: intact, but not authenticated."
