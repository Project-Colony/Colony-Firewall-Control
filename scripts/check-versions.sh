#!/usr/bin/env bash
# Asserts that the project version is identical everywhere it is hardcoded:
#
#   - Cargo.toml         [workspace.package] version
#   - pkg/PKGBUILD       pkgver=
#   - pkg/colony.json    every "version" field and every version embedded
#                        in an "asset" filename
#   - packaging/rpm/colony-firewall-control.spec   Version:
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

cargo_ver="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p}' "${ROOT}/Cargo.toml" | head -n1)"
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

# pkg/PKGBUILD -> pkgver=X.Y.Z
pkgbuild_ver="$(sed -n 's/^pkgver=//p' "${ROOT}/pkg/PKGBUILD" | head -n1)"
check "pkg/PKGBUILD pkgver" "${pkgbuild_ver}"

# pkg/colony.json -> every "version": "X.Y.Z" field
n=0
while IFS= read -r v; do
    n=$((n + 1))
    check "pkg/colony.json \"version\" field #${n}" "${v}"
done < <(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "${ROOT}/pkg/colony.json" \
    | sed 's/.*:[[:space:]]*"\(.*\)"/\1/')
if [[ "${n}" -eq 0 ]]; then
    mismatches+=("pkg/colony.json: no \"version\" field found")
    fail=1
fi

# pkg/colony.json -> version embedded in every "asset" filename
n=0
while IFS= read -r v; do
    n=$((n + 1))
    check "pkg/colony.json \"asset\" filename #${n}" "${v}"
done < <(grep -oE '"asset"[[:space:]]*:[[:space:]]*"[^"]*"' "${ROOT}/pkg/colony.json" \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
if [[ "${n}" -eq 0 ]]; then
    mismatches+=("pkg/colony.json: no \"asset\" filename with a version found")
    fail=1
fi

# packaging/rpm/colony-firewall-control.spec -> Version: X.Y.Z
spec_ver="$(sed -n 's/^Version:[[:space:]]*//p' "${ROOT}/packaging/rpm/colony-firewall-control.spec" | head -n1)"
check "packaging/rpm/colony-firewall-control.spec Version" "${spec_ver}"

if [[ "${fail}" -ne 0 ]]; then
    echo "version mismatch (canonical: Cargo.toml [workspace.package] = ${cargo_ver}):" >&2
    for m in "${mismatches[@]}"; do
        echo "  - ${m}" >&2
    done
    exit 1
fi

echo "versions consistent: ${cargo_ver}"
