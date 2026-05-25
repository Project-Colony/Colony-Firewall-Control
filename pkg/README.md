# Packaging

## Arch Linux (AUR)

`PKGBUILD` builds and installs all three binaries plus the systemd unit. From
the repo root:

```sh
cp pkg/PKGBUILD ./
makepkg -si
```

When the package matures, push to AUR as `colony-firewall-control`.

## Colony app store

`colony.json` follows the Colony manifest format (camelCase, single asset
per platform). Build a release tarball with:

```sh
cargo build --workspace --release
tar --zstd -cf colony-firewall-control-0.1.0-linux-x86_64.tar.zst \
    -C target/release colony-firewalld colony-firewall cfc \
    -C ../../systemd colony-firewalld.service daemon.toml.sample
```

Then upload the tarball as a GitHub Release asset and link it from the
`asset` field of `colony.json`.

## Manual install

After `cargo build --release`:

```sh
sudo install -Dm755 target/release/colony-firewalld /usr/bin/colony-firewalld
sudo install -Dm755 target/release/colony-firewall  /usr/bin/colony-firewall
sudo install -Dm755 target/release/cfc              /usr/bin/cfc
sudo install -Dm644 systemd/colony-firewalld.service /usr/lib/systemd/system/
sudo install -Dm644 systemd/daemon.toml.sample /etc/colony-firewall/daemon.toml
sudo systemctl daemon-reload
sudo systemctl enable --now colony-firewalld
```

Then enqueue traffic with the nftables snippet:

```sh
sudo nft -f systemd/nftables-snippet.conf
```
