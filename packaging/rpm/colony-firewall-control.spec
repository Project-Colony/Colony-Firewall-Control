%global forgeurl https://github.com/Project-Colony/Colony-Firewall-Control
%global selinuxtype targeted
%global modulename colony_firewall

Name:           colony-firewall-control
Version:        0.2.0
Release:        1%{?dist}
Summary:        Application-aware outbound firewall for Linux

License:        GPL-3.0-or-later
URL:            %{forgeurl}
Source0:        %{forgeurl}/archive/v%{version}/%{name}-%{version}.tar.gz

ExclusiveArch:  x86_64

BuildRequires:  cargo
BuildRequires:  rust >= 1.88
BuildRequires:  protobuf-compiler
BuildRequires:  pkgconf
BuildRequires:  gcc
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel

# nft(8) is required by colony-firewall-nft.service and by the uninstall
# cleanup. Everything else the daemon needs it speaks itself: the nfq crate
# talks netlink directly rather than linking libnetfilter_queue, and rusqlite
# is built with the bundled feature.
Requires:       nftables
Requires:       (%{name}-selinux if selinux-policy-%{selinuxtype})
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

# The GUI dlopen's these; the daemon, CLI and tray do not need them, which is
# why they are weak. A headless server installs none of them.
Recommends:     libxkbcommon
Recommends:     wayland
Suggests:       libnotify

%description
Colony Firewall Control asks before a program is allowed to reach the network,
the way Windows Firewall Control does, and remembers the answer per executable.

Filtering happens in nftables via NFQUEUE; the daemon attributes each flow to
the process that opened it and either applies a stored rule or prompts. On a
kernel with BPF available it additionally attaches five small eBPF programs:
three that improve attribution and hostname resolution, and two that refuse
connect(2) in the kernel for programs already denied - pinned to bpffs, so
those denials survive the daemon being killed.

The ruleset is fail-closed. If the daemon is not running, new outbound
connections are dropped rather than allowed.

%package selinux
Summary:        SELinux policy module for %{name}
BuildArch:      noarch
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
Requires(post): policycoreutils
Requires(postun): policycoreutils
%{?selinux_requires}

%description selinux
SELinux policy module for Colony Firewall Control.

Confines the daemon to what it actually needs: netlink_netfilter and raw
sockets, bpf() and perf_event_open(), the bpffs pin directory, other domains'
/proc entries for attribution, and a read-only rpm query for package
provenance. CAP_SYS_ADMIN is deliberately not granted; that it is unnecessary
is covered by a test rather than assumed.

%prep
%autosetup -n Colony-Firewall-Control-%{version}

%build
export CARGO_TARGET_DIR=target
cargo build --workspace --profile release --locked

# The eBPF object is deliberately NOT built here. It needs a pinned nightly,
# -Z build-std and a matching bpf-linker, none of which belong in a distro
# build root. Without it the daemon reports Degrade::ObjectMissing once and
# runs on sock_diag + /proc, which is a supported configuration - see
# docs/TROUBLESHOOTING.md. Users who want the ring-0 layer build it with
# `cargo xtask build-ebpf` and drop the object at
# /usr/lib/colony-firewall/cfc-ebpf.o.

pushd packaging/selinux
make -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp
bzip2 -9 %{modulename}.pp
popd

%install
install -Dpm 0755 target/release/colony-firewalld     %{buildroot}%{_bindir}/colony-firewalld
install -Dpm 0755 target/release/colony-firewall      %{buildroot}%{_bindir}/colony-firewall
install -Dpm 0755 target/release/colony-firewall-tray %{buildroot}%{_bindir}/colony-firewall-tray
install -Dpm 0755 target/release/cfc                  %{buildroot}%{_bindir}/cfc

install -Dpm 0644 systemd/colony-firewalld.service \
    %{buildroot}%{_unitdir}/colony-firewalld.service
install -Dpm 0644 systemd/colony-firewall-nft.service \
    %{buildroot}%{_unitdir}/colony-firewall-nft.service
install -Dpm 0644 systemd/colony-firewall-nft-inbound.service \
    %{buildroot}%{_unitdir}/colony-firewall-nft-inbound.service
install -Dpm 0644 systemd/colony-firewall.sysusers \
    %{buildroot}%{_sysusersdir}/colony-firewall.conf

install -Dpm 0644 systemd/daemon.toml.sample \
    %{buildroot}%{_sysconfdir}/colony-firewall/daemon.toml
install -Dpm 0644 systemd/nftables-snippet.conf \
    %{buildroot}%{_datadir}/colony-firewall/nftables-snippet.conf
install -Dpm 0644 systemd/nftables-inbound.conf \
    %{buildroot}%{_datadir}/colony-firewall/nftables-inbound.conf
install -Dpm 0755 scripts/inbound-lockout-guard.sh \
    %{buildroot}%{_prefix}/lib/colony-firewall/inbound-lockout-guard.sh

install -Dpm 0644 pkg/colony-firewall.desktop \
    %{buildroot}%{_datadir}/applications/colony-firewall.desktop
install -Dpm 0644 pkg/colony-firewall-autostart.desktop \
    %{buildroot}%{_sysconfdir}/xdg/autostart/colony-firewall.desktop
install -Dpm 0644 pkg/colony-firewall-tray-autostart.desktop \
    %{buildroot}%{_sysconfdir}/xdg/autostart/colony-firewall-tray.desktop
install -Dpm 0644 pkg/colony-firewall.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/colony-firewall.svg

# Where the eBPF object goes if one is installed later. Shipping the directory
# means the loader's ownership check (root-owned, unwritable by anyone else)
# passes for a file dropped into it, instead of failing on a directory the user
# had to create by hand.
install -dpm 0755 %{buildroot}%{_prefix}/lib/colony-firewall

install -Dpm 0644 packaging/selinux/%{modulename}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -Dpm 0644 packaging/selinux/%{modulename}.if \
    %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{modulename}.if

# Completions and man pages come out of the binary just built, so they cannot
# drift from the actual CLI surface. Neither subcommand talks to the daemon,
# which is what makes this work in a build root.
target/release/cfc completions bash >cfc.bash
target/release/cfc completions zsh  >_cfc
target/release/cfc completions fish >cfc.fish
target/release/cfc man --dir man

install -Dpm 0644 cfc.bash %{buildroot}%{_datadir}/bash-completion/completions/cfc
install -Dpm 0644 _cfc     %{buildroot}%{_datadir}/zsh/site-functions/_cfc
install -Dpm 0644 cfc.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/cfc.fish
install -dpm 0755 %{buildroot}%{_mandir}/man1
install -pm 0644 man/*.1 %{buildroot}%{_mandir}/man1/

%check
# Dev profile: the release profile sets panic=abort, which the libtest harness
# cannot use. The eBPF live tests are #[ignore]d and need root, so they do not
# run here.
cargo test --workspace --locked --no-fail-fast

%post
%systemd_post colony-firewalld.service colony-firewall-nft.service
%sysusers_create_compat %{_sysusersdir}/colony-firewall.conf

%preun
%systemd_preun colony-firewalld.service colony-firewall-nft.service

%postun
%systemd_postun_with_restart colony-firewalld.service
if [ $1 -eq 0 ]; then
    # The ruleset is fail-closed, so leaving the table behind on uninstall
    # would leave the machine with no outbound network and no daemon to
    # explain why. The BPF pins are the same story: they hold denials in the
    # kernel and nothing would be left to steer or remove them.
    nft delete table inet colony_firewall 2>/dev/null || :
    rm -rf /sys/fs/bpf/colony-firewall 2>/dev/null || :
fi

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2

%postun selinux
if [ $1 -eq 0 ]; then
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files
%license LICENSE
%doc README.md docs/ARCHITECTURE.md docs/HARDENING.md docs/TROUBLESHOOTING.md
%{_bindir}/colony-firewalld
%{_bindir}/colony-firewall
%{_bindir}/colony-firewall-tray
%{_bindir}/cfc
%{_unitdir}/colony-firewalld.service
%{_unitdir}/colony-firewall-nft.service
%{_sysusersdir}/colony-firewall.conf
%config(noreplace) %{_sysconfdir}/colony-firewall/daemon.toml
%dir %{_sysconfdir}/colony-firewall
%dir %{_datadir}/colony-firewall
%{_datadir}/colony-firewall/nftables-snippet.conf
%{_unitdir}/colony-firewall-nft-inbound.service
%{_datadir}/colony-firewall/nftables-inbound.conf
%dir %{_prefix}/lib/colony-firewall
%attr(0755,root,root) %{_prefix}/lib/colony-firewall/inbound-lockout-guard.sh
%dir %{_prefix}/lib/colony-firewall
%{_datadir}/applications/colony-firewall.desktop
%{_sysconfdir}/xdg/autostart/colony-firewall.desktop
%{_sysconfdir}/xdg/autostart/colony-firewall-tray.desktop
%{_datadir}/icons/hicolor/scalable/apps/colony-firewall.svg
%{_datadir}/bash-completion/completions/cfc
%{_datadir}/zsh/site-functions/_cfc
%{_datadir}/fish/vendor_completions.d/cfc.fish
%{_mandir}/man1/cfc*.1*

%files selinux
%doc packaging/selinux/README.md
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if

%changelog
* Wed Aug 19 2026 MotherSphere <linhajahad@gmail.com> - 0.2.0-1
- First RPM packaging, with an SELinux policy module.
- rpm provenance backend: binaries on this platform can now be verified
  against their package rather than reporting as unpackaged.
