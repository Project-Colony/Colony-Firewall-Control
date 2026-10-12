//! The bundles `cfc rules bundle` and `bootstrap-defaults` install: what each
//! entry allows, and what older releases installed for it.

use cfc_client::proto;
use std::path::PathBuf;

/// One rule a bundle would install.
///
/// # Every entry names an executable. On purpose.
///
/// A bundle must never install a bare "allow tcp/443". That is precisely the
/// hole this program exists to close: a payload phoning home uses 443 exactly
/// like a browser does, and a port-shaped rule cannot tell them apart. What
/// makes a rule worth having is the pairing - *this binary* may reach *this
/// port* - so `exe_candidates` is not optional and there is no way to express
/// a rule without it.
///
/// # Why a list of candidates
///
/// Binary paths differ per distribution: `/usr/bin/NetworkManager` on Arch,
/// `/usr/sbin/NetworkManager` on Debian. Hardcoding one path would make a
/// bundle silently install nothing useful on half the machines that run it.
/// The first candidate that **exists on this machine** is used; if none does,
/// the entry is skipped and said out loud, so "installed 4 of 7, skipped 3 not
/// present" is a normal, legible outcome rather than a silent partial success.
///
/// # Candidates name the program that connects
///
/// The daemon matches `/proc/<pid>/exe`, the image that was mapped. A launcher
/// script (`/usr/bin/firefox` on Arch), a proxy that execs another binary
/// (rustup's `cargo`) or a front end whose helper does the fetching (`git`,
/// `apt-get`) never appears there, so a rule pinned to it never fires. Real
/// binaries come first, and launchers are skipped (see [`is_launcher`]).
/// Tools where only an interpreter connects (npm, pip) are not bundled at all:
/// allowing `/usr/bin/node` to reach 443 would allow every Node program.
#[derive(Clone, Copy)]
pub(super) struct BundleRule {
    pub(super) name: &'static str,
    /// Absolute paths to try, in order. First one that exists wins.
    ///
    /// Empty for an inbound entry: inbound rules are about ports and peers,
    /// not about which program happens to be listening. Requiring an exe there
    /// would also make the rule stop working the day the service is replaced -
    /// exactly when you least want your SSH rule to evaporate.
    pub(super) exe_candidates: &'static [&'static str],
    pub(super) dst_port: Option<u16>,
    pub(super) protocol: Option<proto::Protocol>,
    /// `Some(Inbound)` makes this an inbound rule; `None` leaves the rule
    /// direction-agnostic, which is what every pre-existing bundle entry is.
    pub(super) direction: Option<proto::Direction>,
    /// Which peers may reach us. Only meaningful with `direction: Inbound`.
    pub(super) src_net: Option<&'static str>,
}

impl BundleRule {
    /// The path to use on this machine, or `None` if the program is not here.
    ///
    /// Bundles deliberately snapshot the current mapped target of a fixed
    /// shipped candidate list. They do not claim to follow a mutable alias.
    pub(super) fn resolve(&self) -> Option<PathBuf> {
        // An entry with no candidates is not "the program is missing", it is
        // "this rule is not about a program". Returning an empty path lets it
        // flow through the same planning and reporting as every other entry.
        if self.exe_candidates.is_empty() {
            return Some(PathBuf::new());
        }
        self.exe_candidates
            .iter()
            .copied()
            .filter(|p| std::path::Path::new(p).is_file())
            .map(|p| cfc_core::exe_path::resolve(std::path::Path::new(p)).into_path())
            .find(|p| !is_launcher(p))
    }

    /// The path 0.3.0 through 0.7.0 pinned: the first candidate that exists,
    /// launcher or not.
    pub(super) fn resolve_pre_0_7(&self) -> Option<PathBuf> {
        if self.exe_candidates.is_empty() {
            return Some(PathBuf::new());
        }
        self.exe_candidates
            .iter()
            .map(std::path::Path::new)
            .find(|p| p.is_file())
            .map(|p| cfc_core::exe_path::resolve(p).into_path())
    }
}

/// True for a file that execs another image instead of connecting itself: a
/// `#!` script, or the rustup proxy every toolchain binary links to.
fn is_launcher(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    if path.file_name() == Some(std::ffi::OsStr::new("rustup")) {
        return true;
    }
    let mut head = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok()
        && head == *b"#!"
}

/// A named, selectable set of rules.
pub(super) struct Bundle {
    pub(super) name: &'static str,
    pub(super) summary: &'static str,
    pub(super) rules: Vec<BundleRule>,
}

/// Every bundle this build knows about.
///
/// `system` is byte-for-byte the set `bootstrap-defaults` has always
/// installed - same twelve rule names, same ports - so that command keeps
/// working and existing installs see no change. What it gains is alternative
/// paths for distributions that put these binaries elsewhere.
pub(super) fn bundles() -> Vec<Bundle> {
    use proto::Protocol::{Tcp, Udp};
    vec![
        Bundle {
            name: "system",
            summary: "what a machine needs to boot, resolve names, keep time and be updated",
            rules: vec![
                // DNS - systemd-resolved owns the stub.
                BundleRule {
                    name: "default-systemd-resolved-dns",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-resolved",
                        "/lib/systemd/systemd-resolved",
                    ],
                    dst_port: Some(53),
                    protocol: None,
                    direction: None,
                    src_net: None,
                },
                // NTP - timesyncd or chrony.
                BundleRule {
                    name: "default-systemd-timesyncd",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-timesyncd",
                        "/lib/systemd/systemd-timesyncd",
                    ],
                    dst_port: Some(123),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-chrony",
                    exe_candidates: &["/usr/bin/chronyd", "/usr/sbin/chronyd"],
                    dst_port: Some(123),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                // Package managers - HTTPS mirrors.
                BundleRule {
                    name: "default-pacman-https",
                    exe_candidates: &["/usr/bin/pacman"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-paru-https",
                    exe_candidates: &["/usr/bin/paru"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                // SSH client.
                BundleRule {
                    name: "default-ssh-client",
                    exe_candidates: &["/usr/bin/ssh"],
                    dst_port: Some(22),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                // DHCP clients. The units are ordered Before=network-pre.target,
                // so filtering is live before any interface is configured: these
                // rules are what lets the machine get a lease at boot with no UI
                // connected yet to answer prompts. (The very first DISCOVER goes
                // over an AF_PACKET raw socket that bypasses netfilter anyway;
                // these cover the routed unicast renewals, v4 on 67/udp and
                // DHCPv6 on 547/udp.)
                BundleRule {
                    name: "default-dhcpcd",
                    exe_candidates: &["/usr/bin/dhcpcd", "/usr/sbin/dhcpcd"],
                    dst_port: Some(67),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-dhcpcd-v6",
                    exe_candidates: &["/usr/bin/dhcpcd", "/usr/sbin/dhcpcd"],
                    dst_port: Some(547),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-networkmanager-dhcp",
                    exe_candidates: &["/usr/bin/NetworkManager", "/usr/sbin/NetworkManager"],
                    dst_port: Some(67),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-networkmanager-dhcp6",
                    exe_candidates: &["/usr/bin/NetworkManager", "/usr/sbin/NetworkManager"],
                    dst_port: Some(547),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-networkd-dhcp",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-networkd",
                        "/lib/systemd/systemd-networkd",
                    ],
                    dst_port: Some(67),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "default-networkd-dhcp6",
                    exe_candidates: &[
                        "/usr/lib/systemd/systemd-networkd",
                        "/lib/systemd/systemd-networkd",
                    ],
                    dst_port: Some(547),
                    protocol: Some(Udp),
                    direction: None,
                    src_net: None,
                },
            ],
        },
        Bundle {
            name: "updates",
            summary: "package managers beyond pacman/paru, which are in `system`",
            rules: vec![
                // apt-get hands the fetch to its method helpers.
                BundleRule {
                    name: "updates-apt-https",
                    exe_candidates: &["/usr/lib/apt/methods/https"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                // Debian mirrors are still commonly plain HTTP; the packages
                // are signed, so the transport is not what protects them.
                BundleRule {
                    name: "updates-apt-http",
                    exe_candidates: &["/usr/lib/apt/methods/http"],
                    dst_port: Some(80),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "updates-dnf-https",
                    exe_candidates: &["/usr/bin/dnf", "/usr/bin/dnf5"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "updates-flatpak-https",
                    exe_candidates: &["/usr/bin/flatpak"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "updates-yay-https",
                    exe_candidates: &["/usr/bin/yay"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
            ],
        },
        Bundle {
            name: "web",
            summary: "installed browsers, for HTTPS and the HTTP that redirects to it",
            rules: browser_rules(),
        },
        Bundle {
            name: "dev",
            summary: "the tools that fetch code and dependencies",
            rules: vec![
                // git speaks both, but through helpers: git-remote-https for
                // HTTPS remotes and ssh for ssh:// remotes.
                BundleRule {
                    name: "dev-git-https",
                    exe_candidates: &[
                        "/usr/lib/git-core/git-remote-https",
                        "/usr/libexec/git-core/git-remote-https",
                    ],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "dev-git-ssh",
                    exe_candidates: &["/usr/bin/ssh"],
                    dst_port: Some(22),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "dev-cargo-https",
                    exe_candidates: &["/usr/bin/cargo"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
                BundleRule {
                    name: "dev-docker-https",
                    exe_candidates: &["/usr/bin/dockerd", "/usr/bin/podman"],
                    dst_port: Some(443),
                    protocol: Some(Tcp),
                    direction: None,
                    src_net: None,
                },
            ],
        },
        // The only bundle whose entries name no executable, because inbound
        // rules are about ports and peers. Tying "SSH may reach me" to a
        // particular sshd binary would make the rule evaporate the day the
        // service is replaced - precisely when you least want it to.
        //
        // Everything here is scoped to private networks. A bundle that opened
        // a port to the whole internet would be the wrong kind of convenient,
        // and someone who wants that can say so in one command.
        Bundle {
            name: "inbound",
            summary: "the inbound traffic a machine on a home or office LAN normally needs",
            rules: vec![
                // Nothing gets in without a rule, so SSH needs one before the
                // inbound chain is worth enabling. LAN-scoped: this is the
                // rule that stops you locking yourself out, not an invitation
                // to the internet.
                BundleRule {
                    name: "inbound-ssh-lan",
                    exe_candidates: &[],
                    dst_port: Some(22),
                    protocol: Some(Tcp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("192.168.0.0/16"),
                },
                // mDNS and LLMNR: how `.local` names resolve, and how printers,
                // speakers and phones announce themselves. Denying these is
                // what makes a LAN feel broken in ways nobody connects back to
                // the firewall - the symptom is a device that "sometimes"
                // disappears.
                // DHCP replies arrive at the client's port 68 from the server.
                // Without this a lease renewal fails and the machine loses its
                // address on a timer measured in hours - the slowest possible
                // way to discover a firewall rule is missing.
                // One entry per private range, because `src_net` holds one
                // CIDR and an unscoped entry is not "the LAN" - it is the
                // internet. These three ports were shipped with `src_net: None`
                // and admitted unicast UDP from any address on earth; mDNS and
                // LLMNR are well-known reflection and spoofing surfaces, so
                // that was the guarantee this bundle exists to uphold being
                // handed away by the bundle itself.
                //
                // The ranges are dual-stack because the inbound chain is: the
                // nftables table is family `inet`, so IPv6 mDNS/LLMNR - sent
                // from neighbours' fe80:: link-local addresses - is filtered
                // too, and a v4-only list silently broke discovery for
                // IPv6-only speakers in exactly the "device that sometimes
                // disappears" way this comment promises to prevent. DHCPv6
                // needs no entry here: the shipped inbound snippet accepts
                // fe80::/10 to ports 546/547 in-kernel, before the queue.
                //
                // A LAN outside RFC1918 needs a hand-written rule. That is the
                // right trade: a missing rule is a visible symptom, an
                // internet-wide hole is not.
                BundleRule {
                    name: "inbound-mdns-lan",
                    exe_candidates: &[],
                    dst_port: Some(5353),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("192.168.0.0/16"),
                },
                BundleRule {
                    name: "inbound-mdns-10",
                    exe_candidates: &[],
                    dst_port: Some(5353),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("10.0.0.0/8"),
                },
                BundleRule {
                    name: "inbound-mdns-172",
                    exe_candidates: &[],
                    dst_port: Some(5353),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("172.16.0.0/12"),
                },
                BundleRule {
                    name: "inbound-mdns-linklocal",
                    exe_candidates: &[],
                    dst_port: Some(5353),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("169.254.0.0/16"),
                },
                BundleRule {
                    name: "inbound-mdns-v6-linklocal",
                    exe_candidates: &[],
                    dst_port: Some(5353),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("fe80::/10"),
                },
                BundleRule {
                    name: "inbound-llmnr-lan",
                    exe_candidates: &[],
                    dst_port: Some(5355),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("192.168.0.0/16"),
                },
                BundleRule {
                    name: "inbound-llmnr-10",
                    exe_candidates: &[],
                    dst_port: Some(5355),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("10.0.0.0/8"),
                },
                BundleRule {
                    name: "inbound-llmnr-172",
                    exe_candidates: &[],
                    dst_port: Some(5355),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("172.16.0.0/12"),
                },
                BundleRule {
                    name: "inbound-llmnr-linklocal",
                    exe_candidates: &[],
                    dst_port: Some(5355),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("169.254.0.0/16"),
                },
                BundleRule {
                    name: "inbound-llmnr-v6-linklocal",
                    exe_candidates: &[],
                    dst_port: Some(5355),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("fe80::/10"),
                },
                BundleRule {
                    name: "inbound-dhcp-client-lan",
                    exe_candidates: &[],
                    dst_port: Some(68),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("192.168.0.0/16"),
                },
                BundleRule {
                    name: "inbound-dhcp-client-10",
                    exe_candidates: &[],
                    dst_port: Some(68),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("10.0.0.0/8"),
                },
                BundleRule {
                    name: "inbound-dhcp-client-172",
                    exe_candidates: &[],
                    dst_port: Some(68),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("172.16.0.0/12"),
                },
                BundleRule {
                    name: "inbound-dhcp-client-linklocal",
                    exe_candidates: &[],
                    dst_port: Some(68),
                    protocol: Some(Udp),
                    direction: Some(proto::Direction::Inbound),
                    src_net: Some("169.254.0.0/16"),
                },
            ],
        },
    ]
}

/// One HTTPS and one HTTP rule per browser this build knows about.
///
/// HTTP is included because a great deal of the web is still reached by an
/// http:// link that redirects; a browser allowed only 443 fails in a way
/// users read as "the internet is broken" rather than "the firewall did that".
fn browser_rules() -> Vec<BundleRule> {
    /// `(rule stem, candidate paths)`.
    const BROWSERS: &[(&str, &[&str])] = &[
        (
            "firefox",
            &[
                "/usr/lib/firefox/firefox",
                "/usr/lib64/firefox/firefox",
                "/usr/bin/firefox",
            ],
        ),
        (
            "librewolf",
            &["/usr/lib/librewolf/librewolf", "/usr/bin/librewolf"],
        ),
        (
            "chromium",
            &["/usr/lib/chromium/chromium", "/usr/bin/chromium"],
        ),
        ("chrome", &["/opt/google/chrome/chrome"]),
        (
            "brave",
            &["/opt/brave.com/brave/brave", "/opt/brave-bin/brave"],
        ),
        ("vivaldi", &["/opt/vivaldi/vivaldi-bin"]),
    ];

    // `&'static str` names are needed by `BundleRule`, and these are built at
    // run time, so the table below is spelled out rather than formatted. It is
    // the price of keeping rule names stable and greppable.
    const HTTPS: u16 = 443;
    const HTTP: u16 = 80;
    let mut out = Vec::with_capacity(BROWSERS.len() * 2);
    for (stem, paths) in BROWSERS {
        for (port, suffix) in [(HTTPS, "https"), (HTTP, "http")] {
            out.push(BundleRule {
                // Leaked once, at startup, for a fixed and tiny set. The
                // alternative is threading lifetimes through the whole bundle
                // type for names that live as long as the process anyway.
                name: Box::leak(format!("web-{stem}-{suffix}").into_boxed_str()),
                exe_candidates: paths,
                dst_port: Some(port),
                protocol: Some(proto::Protocol::Tcp),
                direction: None,
                src_net: None,
            });
        }
    }
    out
}

/// Entries whose candidates changed after 0.7.0, or that were dropped, as
/// 0.3.0 through 0.7.0 shipped them: `(bundle, entry, candidates, port)`, all
/// TCP. Epiphany fetches through the WebKit network process every WebKitGTK
/// app shares, and npm and pip connect as their interpreter, so those went.
const PRE_0_7_CHANGED: &[(&str, &str, &[&str], u16)] = &[
    (
        "updates",
        "updates-apt-https",
        &["/usr/bin/apt-get", "/usr/lib/apt/methods/https"],
        443,
    ),
    (
        "updates",
        "updates-apt-http",
        &["/usr/bin/apt-get", "/usr/lib/apt/methods/http"],
        80,
    ),
    ("dev", "dev-git-https", &["/usr/bin/git"], 443),
    ("dev", "dev-git-ssh", &["/usr/bin/git"], 22),
    (
        "dev",
        "dev-npm-https",
        &["/usr/bin/npm", "/usr/bin/node"],
        443,
    ),
    (
        "dev",
        "dev-pip-https",
        &["/usr/bin/pip", "/usr/bin/pip3"],
        443,
    ),
    (
        "web",
        "web-firefox-https",
        &["/usr/bin/firefox", "/usr/lib/firefox/firefox"],
        443,
    ),
    (
        "web",
        "web-firefox-http",
        &["/usr/bin/firefox", "/usr/lib/firefox/firefox"],
        80,
    ),
    ("web", "web-librewolf-https", &["/usr/bin/librewolf"], 443),
    ("web", "web-librewolf-http", &["/usr/bin/librewolf"], 80),
    (
        "web",
        "web-chromium-https",
        &["/usr/bin/chromium", "/usr/lib/chromium/chromium"],
        443,
    ),
    (
        "web",
        "web-chromium-http",
        &["/usr/bin/chromium", "/usr/lib/chromium/chromium"],
        80,
    ),
    (
        "web",
        "web-chrome-https",
        &["/usr/bin/google-chrome-stable"],
        443,
    ),
    (
        "web",
        "web-chrome-http",
        &["/usr/bin/google-chrome-stable"],
        80,
    ),
    ("web", "web-brave-https", &["/usr/bin/brave"], 443),
    ("web", "web-brave-http", &["/usr/bin/brave"], 80),
    (
        "web",
        "web-vivaldi-https",
        &["/usr/bin/vivaldi-stable"],
        443,
    ),
    ("web", "web-vivaldi-http", &["/usr/bin/vivaldi-stable"], 80),
    ("web", "web-epiphany-https", &["/usr/bin/epiphany"], 443),
    ("web", "web-epiphany-http", &["/usr/bin/epiphany"], 80),
];

/// Every entry of `bundle` as 0.3.0 through 0.7.0 shipped it, dropped ones
/// included.
pub(super) fn pre_0_7_entries(bundle: &Bundle) -> Vec<BundleRule> {
    let changed = PRE_0_7_CHANGED.iter().filter(|(b, ..)| *b == bundle.name);
    bundle
        .rules
        .iter()
        .filter(|r| !PRE_0_7_CHANGED.iter().any(|(_, name, ..)| *name == r.name))
        .copied()
        .chain(changed.map(|&(_, name, exe_candidates, port)| BundleRule {
            name,
            exe_candidates,
            dst_port: Some(port),
            protocol: Some(proto::Protocol::Tcp),
            direction: None,
            src_net: None,
        }))
        .collect()
}
