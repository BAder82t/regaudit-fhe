#!/usr/bin/env bash
# Generate the HTML API reference for regaudit-fhe with pdoc.
#
# Usage:
#   scripts/build_api_docs.sh [output_dir]
#
# Output defaults to site/api/. Requires the dev extra (`pip install -e
# ".[dev]"`), which pins pdoc. The generated directory is git-ignored;
# CI builds it fresh and publishes it as an artifact.
set -euo pipefail

OUT_DIR="${1:-site/api}"

if ! python -c "import pdoc" 2>/dev/null; then
  echo "pdoc is not installed. Run: pip install -e \".[dev]\"" >&2
  exit 1
fi

echo "Building API reference into ${OUT_DIR} ..."
python -m pdoc \
  --docformat numpy \
  --no-show-source \
  -o "${OUT_DIR}" \
  regaudit_fhe

echo "Done. Open ${OUT_DIR}/index.html"
