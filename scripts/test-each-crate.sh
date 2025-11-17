#!/usr/bin/env bash
# Per-crate test runner for the eezo workspace.
# Runs each package separately so failures are clearly isolated in CI (with ::group:: output).
set -euo pipefail

# Discover workspace member package names.
meta_json="$(cargo metadata --no-deps --format-version 1)"
readarray -t packages < <(jq -r '
  . as $meta
  | $meta.workspace_members as $ids
  | [ $meta.packages[]
      | select($ids | index(.id))
      | .name
    ] | .[]' <<<"$meta_json")

failures=0

for pkg in "${packages[@]}"; do
  echo "::group::cargo test -p ${pkg}"
  if ! cargo test -p "$pkg" --all-features --all-targets --color always; then
    echo "::error title=Tests failed::$pkg"
    failures=$((failures+1))
  fi
  echo "::endgroup::"
done

if (( failures > 0 )); then
  echo "One or more crates failed (${failures})."
  exit 1
else
  echo "All crates passed."
fi
