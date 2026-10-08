#!/usr/bin/env bash
# Writes install.sh and uninstall.sh into a staged release tarball directory,
# generated from pkg/colony.json.
#
# No Colony app store client reads that manifest: Colony installs a single
# per-user binary and runs no scripts, so it could not install units, nft
# tables or sysusers anyway. These two scripts are what run its postInstall
# and preRemove lists, so the tarball is a manual channel with a real
# installer. Called by the "Assemble tarball" step of release.yml.
#
# Usage: scripts/tarball-installers.sh <staged-directory>

set -euo pipefail

STAGE="${1:?usage: $0 <staged-directory>}"
MANIFEST="$(cd "$(dirname "$0")/.." && pwd)/pkg/colony.json"
PLATFORM=linux-x86_64

{
    printf '#!/bin/sh\n# Generated from pkg/colony.json. Run as root: sudo ./install.sh\nset -e\ncd "$(dirname "$0")"\n'
    jq -er --arg p "${PLATFORM}" '.platforms[$p]
        | "install -m 0755 \(.binaries | join(" ")) \(.installPath)/", .postInstall[]' "${MANIFEST}"
    printf 'echo "Installed. Enable enforcement as described under First run in README.md."\n'
} >"${STAGE}/install.sh"

{
    printf '#!/bin/sh\n# Generated from pkg/colony.json. Run as root: sudo ./uninstall.sh\nset -e\n'
    jq -er --arg p "${PLATFORM}" '.platforms[$p]
        | .preRemove[], "rm -f \(.installPath as $dir | .binaries | map("\($dir)/\(.)") | join(" "))"' "${MANIFEST}"
} >"${STAGE}/uninstall.sh"

chmod 0755 "${STAGE}/install.sh" "${STAGE}/uninstall.sh"
sh -n "${STAGE}/install.sh"
sh -n "${STAGE}/uninstall.sh"
