#!/usr/bin/env bash
# Build the guest and boot it. The guest's own output is the verdict.
#
#   sudo -v && ./scripts/vm-bench/run.sh
#
# Needs qemu-system-x86_64, KVM, and one `sudo` to read the host kernel image
# (it is copied once into the work directory and then owned by you). Everything
# else is assembled from this machine's own binaries; nothing is downloaded.
#
# Knobs, all optional:
#   KERNEL      the kernel image to boot (default: this machine's)
#   OUT         work directory (default: target/vm-bench)
#   SWEEP       flow counts to measure, e.g. "100 300 1000 3000" (the default)
#   DRAIN_SECS  seconds between states, so each starts on a comparable socket
#               table (default 70, which is one TIME_WAIT)
#   ALT_DAEMON  a second colony-firewalld to carry into the image, measured
#               beside the first. Used to attribute a cost to one constant:
#               build it, point at it, and the plan runs both.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${OUT:-$REPO/target/vm-bench}"
KERNEL="${KERNEL:-/boot/vmlinuz-$(uname -r)}"
[ -e "$KERNEL" ] || KERNEL=/boot/vmlinuz-linux
mkdir -p "$OUT"
export REPO OUT

for f in build-guest.sh init plan.sh; do
    install -m0755 "$REPO/scripts/vm-bench/$f" "$OUT/$f"
done

if [ ! -r "$OUT/vmlinuz" ]; then
    echo "==> kernel ($KERNEL)"
    # Arch ships /boot/vmlinuz-linux mode 0600 root:root; one sudo, once.
    sudo install -m0644 -o "$(id -u)" -g "$(id -g)" "$KERNEL" "$OUT/vmlinuz"
fi

"$OUT/build-guest.sh"

echo "==> boot"
START=$(date +%s)
RC=0
# The guest panics on purpose when its init exits, and -no-reboot turns that
# into a qemu exit: the marker below is the verdict, not this exit code.
timeout "${TIMEOUT:-2700}" qemu-system-x86_64 \
    -enable-kvm -cpu host -m "${MEM:-4G}" -smp "${SMP:-4}" \
    -kernel "$OUT/vmlinuz" -initrd "$OUT/rootfs.cpio.gz" \
    -append "rdinit=/init console=ttyS0 panic=1${SWEEP:+ cfc_sweep=${SWEEP// /,}}${DRAIN_SECS:+ cfc_drain=$DRAIN_SECS}" \
    -nographic -no-reboot > "$OUT/guest.log" 2>&1 || RC=$?
echo "==> qemu exit ${RC} (informational), $(( $(date +%s) - START ))s wall clock"

if ! grep -q 'CFC_DONE=' "$OUT/guest.log"; then
    echo "the guest never reached the end of the plan; see $OUT/guest.log" >&2
    exit 1
fi
python3 "$REPO/scripts/vm-bench/report.py" "$OUT/guest.log" | tee "$OUT/report.txt"
echo
echo "full guest console: $OUT/guest.log"
