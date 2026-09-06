#!/usr/bin/env bash
# Assemble a minimal initramfs that runs Colony Firewall Control for real:
# this machine's own kernel modules, nftables, iproute2, python3 and the
# release binaries. There is no package manager and no network in the guest,
# so everything the daemon or the bench touches has to be put here.
set -euo pipefail

REPO="${REPO:?REPO must point at the checkout}"
OUT="${OUT:?OUT must point at the work directory}"
KREL="$(uname -r)"
RFS="$OUT/rootfs"

rm -rf "$RFS"
# The usr-merge symlinks FIRST. Creating /lib as a directory and turning it
# into a symlink afterwards does not work - ln would drop the link inside it.
mkdir -p "$RFS"/usr/bin "$RFS"/usr/lib
ln -s usr/bin "$RFS/bin"; ln -s usr/bin "$RFS/sbin"
ln -s bin    "$RFS/usr/sbin"
ln -s usr/lib "$RFS/lib"; ln -s usr/lib "$RFS/lib64"
mkdir -p "$RFS"/{proc,sys,tmp,dev,run,root,bench,etc} \
         "$RFS/usr/lib/modules/$KREL" "$RFS"/sys/fs/{cgroup,bpf} "$RFS"/sys/kernel/tracing \
         "$RFS"/etc/colony-firewall "$RFS"/var/{lib,log} \
         "$RFS"/var/lib/colony-firewall "$RFS"/var/log/colony-firewall
ln -s ../run "$RFS/var/run"

copy_file() {  # keeps the path, dereferences: every name the loader may ask
    local src="$1" dst="$RFS$1"
    [ -e "$src" ] || return 1
    [ -e "$dst" ] && return 0
    mkdir -p "$(dirname "$dst")"
    cp -aL "$src" "$dst" 2>/dev/null || return 1
}

missing=""
copy_bin() {
    local name="$1" path real lib rl
    path="$(command -v "$name" 2>/dev/null || true)"
    [ -n "$path" ] || path="$name"
    [ -x "$path" ] || { missing="$missing $name"; return 0; }
    real="$(readlink -f "$path")"
    copy_file "$real" || true
    [ "$real" != "$path" ] && { copy_file "$path" || true; }
    for lib in $(ldd "$real" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' || true); do
        copy_file "$lib" || true
        rl="$(readlink -f "$lib")"
        [ "$rl" != "$lib" ] && { copy_file "$rl" || true; }
    done
    return 0
}

echo "==> binaries"
for b in bash mount umount mkdir rmdir rm cp mv ln cat sleep seq paste cut tr sort uniq \
         head tail wc grep sed gawk env readlink dirname basename chmod chown \
         stat date ip ss nft python3 insmod id find xargs touch sync ls \
         uname hostname mktemp tee expr comm sha256sum install printf sleep; do
    copy_bin "$b"
done
[ -n "$missing" ] && echo "    missing:$missing"
install -m0755 "$REPO/target/release/colony-firewalld" "$RFS/usr/bin/colony-firewalld"
install -m0755 "$REPO/target/release/cfc"              "$RFS/usr/bin/cfc"
# Optional: the same daemon built with a different RECV_POLL_INTERVAL. Both in
# one image so the two can be measured in a single boot, under conditions that
# differ in nothing else.
if [ -x "${ALT_DAEMON:-/nonexistent}" ]; then
    install -m0755 "$ALT_DAEMON" "$RFS/usr/bin/colony-firewalld-alt"
    echo "    plus an alternate daemon: $ALT_DAEMON"
fi
copy_bin "$REPO/target/release/colony-firewalld"
copy_bin "$REPO/target/release/cfc"
ln -sf gawk "$RFS/usr/bin/awk"
ln -sf bash "$RFS/usr/bin/sh"

echo "==> python stdlib"
PYDIR="$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')"
mkdir -p "$RFS$(dirname "$PYDIR")"
tar -C "$(dirname "$PYDIR")" -cf - \
    --exclude='test' --exclude='tests' --exclude='__pycache__' --exclude='idlelib' \
    --exclude='tkinter' --exclude='lib2to3' --exclude='ensurepip' --exclude='site-packages' \
    --exclude='config-*' --exclude='pydoc_data' --exclude='turtledemo' \
    "$(basename "$PYDIR")" | tar -C "$RFS$(dirname "$PYDIR")" -xf -
# The stdlib's C extensions have their own shared-object dependencies.
for so in "$RFS$PYDIR"/lib-dynload/*.so; do
    [ -e "$so" ] || continue
    for lib in $(ldd "$so" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' || true); do
        copy_file "$lib" || true
    done
done
true

echo "==> kernel modules"
# Named in dependency order and resolved with `modinfo -n`, not with
# `modprobe --show-depends`. Arch ships an install directive for nf_conntrack
# (it runs sysctl afterwards), so --show-depends prints an `install` line
# rather than an `insmod` one for it - the filter dropped it, the guest booted
# without conntrack, and `ct state new queue num 0` was refused with a bare
# ENOENT. modinfo answers about the module file itself and has no such
# indirection.
: > "$OUT/modlist"
for m in nf_defrag_ipv4 nf_defrag_ipv6 nf_conntrack nf_tables nft_ct nft_queue \
         nfnetlink_queue veth x_tables; do
    ko="$(modinfo -n "$m" 2>/dev/null || true)"
    if [ -n "$ko" ] && copy_file "$ko"; then
        echo "$ko" >> "$OUT/modlist"
    else
        echo "    $m: built in or absent, nothing to carry"
    fi
done
install -m0644 "$OUT/modlist" "$RFS/modlist"
echo "    $(wc -l < "$OUT/modlist") modules"

echo "==> the daemon's own files"
install -m0644 "$REPO/crates/cfc-ebpf/target/bpfel-unknown-none/release/cfc-ebpf.o" "$RFS/cfc-ebpf.o"
install -m0644 "$REPO/systemd/nftables-snippet.conf" "$RFS/etc/colony-firewall/nftables-snippet.conf"
install -m0755 "$REPO/scripts/bench-latency.sh" "$RFS/bench/bench-latency.sh"
install -m0755 "$OUT/plan.sh" "$RFS/bench/plan.sh"
install -m0755 "$OUT/init"    "$RFS/init"

printf 'root:x:0:0:root:/root:/bin/bash\n'            > "$RFS/etc/passwd"
printf 'root:x:0:\ncolony-firewall:x:970:\n'          > "$RFS/etc/group"
printf 'passwd: files\ngroup: files\nhosts: files\n'  > "$RFS/etc/nsswitch.conf"
printf '127.0.0.1 localhost\n'                        > "$RFS/etc/hosts"
printf 'guest\n'                                      > "$RFS/etc/hostname"
cp -aL /etc/protocols /etc/services "$RFS/etc/" 2>/dev/null || true

echo "==> pack"
( cd "$RFS" && find . | cpio -o -H newc --owner=0:0 --quiet | gzip -1 ) > "$OUT/rootfs.cpio.gz"
du -sh "$RFS" "$OUT/rootfs.cpio.gz" | awk '{print "    "$1"\t"$2}'
