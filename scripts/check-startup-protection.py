#!/usr/bin/env python3
"""Check startup dependencies and the inbound guard without touching host services."""

import configparser
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MANAGERS = ("NetworkManager.service", "systemd-networkd.service")


def unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.read(ROOT / "systemd" / name)
    return parser


daemon = unit("colony-firewalld.service")
outbound = unit("colony-firewall-nft.service")
assert "colony-firewall-nft.service" in daemon["Unit"].get("Requires", "").split(), \
    "Daemon startup must require installed filtering"
assert "colony-firewall-nft.service" in daemon["Unit"].get("After", "").split()
assert "colony-firewalld.service" not in outbound["Unit"].get("After", "").split()
assert "colony-firewalld.service" not in outbound["Unit"].get("Requires", "").split()

# %systemd_preun stops with --no-reload, under the managers' loaded Requires=,
# which would stop NetworkManager on erase. A reload-first disable must run
# before it.
spec = (ROOT / "packaging/rpm/colony-firewall-control.spec").read_text()
preun = spec.split("\n%preun\n", 1)[1].split("\n%postun", 1)[0]
before_macro = preun.split("\n%systemd_preun", 1)[0]
disable = [line for line in before_macro.splitlines() if "systemctl disable --now" in line]
assert disable and "--no-reload" not in disable[0] and all(
    name in disable[0] for name in ("colony-firewall-nft.service", "colony-firewall-nft-inbound.service")), \
    "RPM erase must disable the nft units with a reload before %systemd_preun stops them"

with tempfile.TemporaryDirectory(prefix="cfc-startup-check-") as directory:
    stage = Path(directory)
    units = stage / "usr/lib/systemd/system"
    units.mkdir(parents=True)
    for source in (ROOT / "systemd").glob("*.service"):
        shutil.copyfile(source, units / source.name)
    for manager in MANAGERS:
        (units / manager).write_text("[Service]\nExecStart=/bin/true\n")
    subprocess.run(["systemctl", "--root", str(stage), "enable", "colony-firewalld.service"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for manager in MANAGERS:
        assert (stage / "etc/systemd/system" / (manager + ".requires") /
                "colony-firewall-nft.service").is_symlink()
        assert not (stage / "etc/systemd/system" / (manager + ".requires") /
                    "colony-firewall-nft-inbound.service").is_symlink()
    subprocess.run(["systemctl", "--root", str(stage), "disable", "colony-firewalld.service"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for name in ("colony-firewall-nft.service", "colony-firewall-nft-inbound.service"):
        definition = unit(name)
        before = definition["Unit"]["Before"].split()
        assert {"colony-firewalld.service", "network-pre.target", *MANAGERS} <= set(before)
        assert "nftables.service" in definition["Unit"]["After"].split()
        assert "is-active" not in definition["Service"].get("ExecStartPre", "")
        subprocess.run(["systemctl", "--root", str(stage), "enable", name], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for manager in MANAGERS:
            dependency = stage / "etc/systemd/system" / (manager + ".requires") / name
            assert dependency.is_symlink(), f"{manager} must require enabled {name}"
        subprocess.run(["systemctl", "--root", str(stage), "disable", name], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for manager in MANAGERS:
            assert not (stage / "etc/systemd/system" / (manager + ".requires") / name).is_symlink()

    # An upgrade must not re-enable an nft unit the admin disabled: reenabling
    # the daemon would bring it back through Also=.
    shim = stage / "shim"
    shim.mkdir()
    (shim / "systemctl").write_text(
        "#!/bin/sh\ncase \"$1\" in daemon-reload|try-reload-or-restart) exit 0 ;; esac\n"
        f"exec {shlex.quote(shutil.which('systemctl'))} --root {shlex.quote(str(stage))} \"$@\"\n")
    (shim / "systemctl").chmod(0o755)
    subprocess.run(["systemctl", "--root", str(stage), "enable", "colony-firewalld.service"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["systemctl", "--root", str(stage), "disable", "colony-firewall-nft.service"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    subprocess.run(["bash", "-c", '. "$1" && post_upgrade >/dev/null', "post_upgrade",
                    str(ROOT / "pkg/colony-firewall-control.install")],
                   env=dict(os.environ, PATH=f"{shim}:{os.environ['PATH']}"), check=True)
    for manager in MANAGERS:
        assert not (stage / "etc/systemd/system" / (manager + ".requires") /
                    "colony-firewall-nft.service").is_symlink(), "upgrade re-enabled a disabled nft unit"
    loop = "for unit in colony-firewall-nft.service colony-firewall-nft-inbound.service; do"
    for recipe in ("pkg/colony-firewall-control.install", "packaging/rpm/colony-firewall-control.spec",
                   "pkg/colony.json"):
        assert loop in (ROOT / recipe).read_text(), f"{recipe} must reenable only enabled nft units"
    subprocess.run(["systemctl", "--root", str(stage), "disable", "colony-firewalld.service"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    binaries = stage / "bin"
    binaries.mkdir()
    ss = binaries / "ss"
    ss.write_text("#!/bin/sh\ncase \"$*\" in\n"
                  "  -Hltn) echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*' ;;\n"
                  "  *) echo '0 0 192.0.2.1:22 192.0.2.2:50123' ;;\nesac\n")
    ss.chmod(0o755)
    db = stage / "rules.db"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE rules (id TEXT, enabled INTEGER, data TEXT)")
        connection.execute("INSERT INTO rules VALUES ('ssh', 1, ?)", (json.dumps({
            "action": "Allow", "duration": "Always", "enabled": True,
            "scope": {"direction": "In", "dst_port": 22},
        }),))
    config = stage / "daemon.toml"
    config.write_text('[storage]\npath = ' + json.dumps(str(db)) + '\n')
    environment = dict(os.environ, PATH=str(binaries) + ":" + os.environ["PATH"],
                       CFC_CONFIG=str(config), CFC_BIN="/no/live/daemon/client")
    environment.pop("CFC_INBOUND_FORCE", None)
    environment.pop("CFC_RULES_DB", None)

    def guard():
        return subprocess.run(["sh", str(ROOT / "scripts/inbound-lockout-guard.sh")],
                              env=environment, capture_output=True, text=True)

    allowed = guard()
    assert allowed.returncode == 0, allowed.stderr
    environment["CFC_CONFIG"] = "/no/config"
    environment["CFC_RULES_DB"] = str(db)
    assert guard().returncode == 0, "Explicit database path must work without TOML parsing"
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE rules SET data = ?", (json.dumps({
            "action": "Allow", "duration": "UntilRestart", "enabled": True,
            "scope": {"direction": "In", "dst_port": 22},
        }),))
    assert guard().returncode != 0, "Transient rules cannot admit persistent inbound filtering"
    db.write_bytes(b"unreadable rule database")
    assert guard().returncode != 0, "Unreadable saved rules cannot vouch for remote access"
    ss.write_text("#!/bin/sh\nexit 0\n")
    assert guard().returncode == 0, "Boot filtering must not require a live daemon or rule database"

print("startup dependencies and offline inbound guard passed")
