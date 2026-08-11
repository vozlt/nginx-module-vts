#!/bin/sh

# Publishes the line rate of a Cobertura report as a shields.io endpoint file
# on the `badges` branch, which the badge in README.md reads.
#
# The branch holds that one file and nothing else. Each run replaces it with a
# single commit and force pushes, so the branch does not grow and never shares
# history with the code.
#
# usage: coverage-badge.sh <cobertura xml>
#
# expects GITHUB_TOKEN and GITHUB_REPOSITORY in the environment.

set -eu

xml=${1:?usage: $0 <cobertura xml>}
branch=badges

: "${GITHUB_TOKEN:?GITHUB_TOKEN is not set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

rate=$(python3 - "$xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()

print(round(float(root.get("line-rate")) * 100, 1))
PY
)

# the thresholds the summary in the workflow reports against
color=$(python3 - "$rate" <<'PY'
import sys

rate = float(sys.argv[1])

print("red" if rate < 60 else "yellow" if rate < 80 else "brightgreen")
PY
)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/coverage.json" <<EOF
{
  "schemaVersion": 1,
  "label": "coverage",
  "message": "$rate%",
  "color": "$color"
}
EOF

cd "$tmp"

git init -q
git checkout -q -b "$branch"
git add coverage.json
git -c user.name='github-actions[bot]' \
    -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    commit -q -m "coverage: $rate% of the lines"
git push -q --force \
    "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}" "$branch"

echo "published $rate% ($color) to the $branch branch"
