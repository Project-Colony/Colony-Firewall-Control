# Packaging

Everything a package ships, at a glance:

| File (repo)                          | Installed to                                              |
| ------------------------------------ | --------------------------------------------------------- |
| `colony-firewalld`, `colony-firewall`, `cfc` | `/usr/bin/`                                       |
| `systemd/colony-firewalld.service`   | `/usr/lib/systemd/system/`                                |
| `systemd/colony-firewall-nft.service`| `/usr/lib/systemd/system/`                                |
| `systemd/colony-firewall.sysusers`   | `/usr/lib/sysusers.d/colony-firewall.conf`                |
| `systemd/daemon.toml.sample`         | `/etc/colony-firewall/daemon.toml` (config, never clobbered) |
| `systemd/nftables-snippet.conf`      | `/usr/share/colony-firewall/nftables-snippet.conf`        |
| `pkg/colony-firewall.desktop`        | `/usr/share/applications/`                                |
| `pkg/colony-firewall-autostart.desktop` | `/etc/xdg/autostart/colony-firewall.desktop`           |
| `pkg/colony-firewall.svg`            | `/usr/share/icons/hicolor/scalable/apps/`                 |
| `README.md`, `docs/{ARCHITECTURE,HARDENING}.md` | `/usr/share/doc/colony-firewall-control/`      |
| `LICENSE`                            | `/usr/share/licenses/colony-firewall-control/`            |

Key design points:

- **`colony-firewall-nft.service`** makes enforcement persistent
  (`nft -f` the snippet on start, `nft delete table inet colony_firewall`
  on stop). It is `PartOf=colony-firewalld.service`, so stopping the
  daemon also removes the fail-closed NFQUEUE table — no more manual
  `nft -f` that vanishes on reboot, and no blackhole when the daemon is
  down on purpose.
- **`colony-firewall.sysusers`** creates the `colony-firewall` group used
  to gate access to the daemon's gRPC UNIX socket. Users join with
  `usermod -aG colony-firewall <user>`.
- **XDG autostart** launches the GUI in every desktop session so prompts
  actually reach the user. Per-user opt-out: copy the file to
  `~/.config/autostart/` and set `Hidden=true`.

## Arch Linux (AUR)

`PKGBUILD` is the release recipe: it builds from the GitHub tag tarball
(`v$pkgver`) and is AUR-submittable. Per release:

```sh
# 1. Tag and push vX.Y.Z on GitHub, bump pkgver in PKGBUILD.
# 2. Fill in the real checksum (replaces the 'SKIP' placeholder):
cd pkg && updpkgsums PKGBUILD          # from pacman-contrib
# 3. Test build (needs colony-firewall-control.install next to PKGBUILD):
mkdir /tmp/cfc-build && cp PKGBUILD colony-firewall-control.install /tmp/cfc-build/
cd /tmp/cfc-build && makepkg -si
# 4. Regenerate .SRCINFO and push to the AUR:
makepkg --printsrcinfo > .SRCINFO
git clone ssh://aur@aur.archlinux.org/colony-firewall-control.git aur
cp PKGBUILD colony-firewall-control.install .SRCINFO aur/ && cd aur
git add -A && git commit -m "Update to X.Y.Z" && git push
```

The install scriptlet (`colony-firewall-control.install`) prints first-run
steps on install (enable units, join the `colony-firewall` group,
`cfc rules bootstrap-defaults`) and — critically — its `pre_remove` stops
`colony-firewall-nft` + `colony-firewalld` and deletes
`table inet colony_firewall`, so removing the package can never leave the
fail-closed queue rule behind and blackhole outbound traffic.

Commented lines in `package()` for shell completions and the `cfc.1` man
page become active once `cfc` learns to generate them (planned).

### -git developer variant

`PKGBUILD-git` builds `colony-firewall-control-git` from the git HEAD with
a `pkgver()` derived from `git describe` (e.g. `0.1.0.r5.gabc1234`). It
`provides`/`conflicts` the release package. To iterate on a local checkout
instead of GitHub, set `_giturl="git+file:///path/to/Colony-Firewall-Control"`
at the top of the file. Usage is documented in its header comment.

## Colony app store

`colony.json` follows the Colony manifest format (camelCase, single asset
per platform). Notes on this manifest:

- `postInstall` is **idempotent**: `daemon.toml` is only installed if
  absent, so upgrades never clobber user config.
- `preRemove` mirrors the pacman `pre_remove`: stop the units, delete
  `table inet colony_firewall`, then remove the non-binary files
  `postInstall` placed (user config in `/etc/colony-firewall/` is kept).
  Stores too old to know the `preRemove` key ignore it — on those, run the
  `preRemove` commands manually before uninstalling, or outbound traffic
  stays blackholed by the orphaned fail-closed table.

Build the release tarball (flat layout; `postInstall`/`preRemove` paths
assume these exact basenames):

```sh
cargo build --workspace --release
tar --zstd -cf colony-firewall-control-0.1.0-linux-x86_64.tar.zst \
    -C target/release colony-firewalld colony-firewall cfc \
    -C ../../systemd colony-firewalld.service colony-firewall-nft.service \
        daemon.toml.sample nftables-snippet.conf colony-firewall.sysusers \
    -C ../pkg colony-firewall.desktop colony-firewall-autostart.desktop \
        colony-firewall.svg
```

Then upload the tarball as a GitHub Release asset and link it from the
`asset` field of `colony.json`.

## Manual install

After `cargo build --release`:

```sh
sudo install -Dm755 target/release/colony-firewalld /usr/bin/colony-firewalld
sudo install -Dm755 target/release/colony-firewall  /usr/bin/colony-firewall
sudo install -Dm755 target/release/cfc              /usr/bin/cfc
sudo install -Dm644 systemd/colony-firewalld.service     /usr/lib/systemd/system/colony-firewalld.service
sudo install -Dm644 systemd/colony-firewall-nft.service  /usr/lib/systemd/system/colony-firewall-nft.service
sudo install -Dm644 systemd/colony-firewall.sysusers     /usr/lib/sysusers.d/colony-firewall.conf
sudo install -Dm644 systemd/nftables-snippet.conf /usr/share/colony-firewall/nftables-snippet.conf
sudo install -Dm644 systemd/daemon.toml.sample /etc/colony-firewall/daemon.toml
sudo install -Dm644 pkg/colony-firewall.desktop /usr/share/applications/colony-firewall.desktop
sudo install -Dm644 pkg/colony-firewall-autostart.desktop /etc/xdg/autostart/colony-firewall.desktop
sudo install -Dm644 pkg/colony-firewall.svg /usr/share/icons/hicolor/scalable/apps/colony-firewall.svg
sudo systemd-sysusers
sudo systemctl daemon-reload
sudo systemctl enable --now colony-firewalld colony-firewall-nft
sudo usermod -aG colony-firewall "$USER"   # then log out/in
cfc rules bootstrap-defaults
```

`colony-firewall-nft` replaces the old manual `nft -f
systemd/nftables-snippet.conf` step and survives reboots.

## Uninstall behavior (all channels)

Order matters because the nftables snippet is fail-closed:

1. `systemctl disable --now colony-firewall-nft colony-firewalld`
   (stopping the nft unit runs `nft delete table inet colony_firewall`).
2. `nft delete table inet colony_firewall || true` as a belt-and-braces
   repeat, in case the table was loaded manually.
3. Remove files. `/etc/colony-firewall/daemon.toml` is user config and is
   left behind (pacman saves it as `.pacsave`).

The AUR package does this automatically via `pre_remove`; the Colony
manifest via `preRemove`; manual installs should follow the steps above.
