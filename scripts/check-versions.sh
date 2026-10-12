#!/usr/bin/env bash
# Asserts that the project version is identical everywhere it is hardcoded:
#
#   - Cargo.toml                         [workspace.package] version
#   - packaging/arch/PKGBUILD            pkgver=
#   - packaging/tarball-manifest.json    every "version" field
#   - packaging/rpm/colony-firewall-control.spec   Version:
#   - crates/cfc-ebpf/Cargo.lock   the `cfc-ebpf-proto` entry. The kernel
#                                  crate is its own workspace with its own
#                                  committed lock, and nothing builds it with
#                                  --locked, so a bump that regenerated only
#                                  the root lock shipped 0.3.0 with this one
#                                  still saying 0.2.3, and 0.4.0 nearly did
#                                  the same.
#
# release-please rewrites every one of these in its release PR (extra-files in
# release-please-config.json); this script is what notices a file it missed.
#
# The spec is here because the job that compared it lived in rhel.yml, which
# only runs when packaging paths change - so a version bump that touched none
# of them shipped a 0.3.0 tree with a spec still saying 0.2.3, and nothing ran
# to say so. This script runs on every push.
#
# Exits non-zero listing every mismatch. Wired into CI (check.yml).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail=0
mismatches=()

cargo_ver="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\([^"]*\)".*/\1/p}' "${ROOT}/Cargo.toml" | head -n1)"
if [[ -z "${cargo_ver}" ]]; then
    echo "error: could not extract version from Cargo.toml [workspace.package]" >&2
    exit 1
fi

check() {
    local what="$1" found="$2"
    if [[ -z "${found}" ]]; then
        mismatches+=("${what}: no version found")
        fail=1
    elif [[ "${found}" != "${cargo_ver}" ]]; then
        mismatches+=("${what}: ${found} (expected ${cargo_ver})")
        fail=1
    fi
}

# packaging/arch/PKGBUILD -> pkgver=X.Y.Z
pkgbuild_ver="$(sed -n 's/^pkgver=//p' "${ROOT}/packaging/arch/PKGBUILD" | head -n1)"
check "packaging/arch/PKGBUILD pkgver" "${pkgbuild_ver}"

# packaging/tarball-manifest.json -> every "version": "X.Y.Z" field
n=0
while IFS= read -r v; do
    n=$((n + 1))
    check "packaging/tarball-manifest.json \"version\" field #${n}" "${v}"
done < <(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${ROOT}/packaging/tarball-manifest.json" \
    | sed 's/.*:[[:space:]]*"\(.*\)"/\1/')
if [[ "${n}" -eq 0 ]]; then
    mismatches+=("packaging/tarball-manifest.json: no \"version\" field found")
    fail=1
fi

# packaging/rpm/colony-firewall-control.spec -> Version: X.Y.Z
spec_ver="$(sed -n 's/^Version:[[:space:]]*//p' "${ROOT}/packaging/rpm/colony-firewall-control.spec" | head -n1)"
check "packaging/rpm/colony-firewall-control.spec Version" "${spec_ver}"

# crates/cfc-ebpf/Cargo.lock -> the version recorded for cfc-ebpf-proto
ebpf_lock_ver="$(awk '/^name = "cfc-ebpf-proto"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' "${ROOT}/crates/cfc-ebpf/Cargo.lock")"
check "crates/cfc-ebpf/Cargo.lock cfc-ebpf-proto" "${ebpf_lock_ver}"

if [[ "${fail}" -ne 0 ]]; then
    echo "version mismatch (canonical: Cargo.toml [workspace.package] = ${cargo_ver}):" >&2
    for m in "${mismatches[@]}"; do
        echo "  - ${m}" >&2
    done
    exit 1
fi

echo "versions consistent: ${cargo_ver}"
