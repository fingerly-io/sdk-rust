#!/usr/bin/env bash
# The version gate release.yml runs. Cargo.toml is the manifest; the code takes
# its version from CARGO_PKG_VERSION, so Cargo.lock is the only duplicate.
#
#   version      print the manifest's version
#   consistency  fail if anything disagrees with the manifest
#   check        print version= and release=true|false for $GITHUB_OUTPUT
set -euo pipefail

die() {
  echo "release-version: $*" >&2
  exit 1
}

# Only a clear yes or no is an answer. An outage has to fail the job, because
# reading it as "not published" would try to release a version that exists.
lookup() {
  local out
  out=$(curl --silent --show-error --location --max-time 30 --retry 3 --retry-all-errors \
    --write-out '\n%{http_code}' "$1") || die "could not reach $1"
  status=${out##*$'\n'}
  body=${out%$'\n'*}
}

# The sparse index is the public, unmetered view of what cargo itself resolves.
on_registry() {
  lookup "https://index.crates.io/fi/ng/fingerly"
  case "$status" in
    200) has_version ;;
    404) return 1 ;;
    *) die "the crates.io index answered $status" ;;
  esac
}

# jq exits 1 for "false" and something else for a body it cannot read, which
# must not pass for "this version is new".
has_version() {
  local rc=0
  jq -s -e --arg v "$version" 'any(.[]; .vers == $v)' <<<"$body" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    *) die "unreadable answer from the crates.io index" ;;
  esac
}

tag_exists() {
  local rc=0
  git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null || rc=$?
  case "$rc" in
    0) return 0 ;;
    2) return 1 ;;
    *) die "git ls-remote failed with $rc" ;;
  esac
}

version=$(awk -F'"' '/^\[/ { in_package = ($0 == "[package]") } in_package && /^version = / { print $2; exit }' Cargo.toml)
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no X.Y.Z version in the manifest: '$version'"

case "${1:-}" in
  version)
    echo "$version"
    ;;
  consistency)
    locked=$(awk -F'"' '$0 == "name = \"fingerly\"" { getline; print $2; exit }' Cargo.lock)
    [ "$locked" = "$version" ] || die "Cargo.lock has $locked, Cargo.toml has $version"
    ;;
  check)
    echo "version=$version"
    if tag_exists; then
      echo "v$version is already tagged" >&2
      echo "release=false"
    elif on_registry; then
      echo "$version is already on crates.io" >&2
      echo "release=false"
    else
      echo "release=true"
    fi
    ;;
  *)
    die "usage: release-version.sh version|consistency|check"
    ;;
esac
