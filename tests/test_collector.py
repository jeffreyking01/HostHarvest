"""
test_collector.py — Unit tests for the CMDB agent collector.

Run with: python -m pytest tests/ -v
"""

import json
import platform
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.collector import (
    collect_python_packages,
    collect_npm_packages,
    collect_java_packages,
    snapshot_to_dict,
    HostSnapshot,
    HardwareInfo,
    NetworkInterface,
    InstalledPackage,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_hardware() -> HardwareInfo:
    return HardwareInfo(
        hostname="test-host", fqdn="test-host.agency.gov",
        os_name="Linux", os_version="5.15.0", os_build="Ubuntu 22.04",
        architecture="x86_64", cpu_model="Intel Xeon", cpu_cores_physical=4,
        cpu_cores_logical=8, ram_gb=16.0, serial_number="SN12345",
        manufacturer="Dell", model="PowerEdge R640",
        bios_version="2.14.0", is_virtual=False, virtualization_platform=None,
    )


# ── Snapshot serialization ─────────────────────────────────────────────────

def test_snapshot_serializes_to_dict():
    snap = HostSnapshot(
        collected_at="2024-01-01T00:00:00+00:00",
        hardware=make_hardware(),
        network_interfaces=[
            NetworkInterface(
                name="eth0", mac_address="aa:bb:cc:dd:ee:ff",
                ipv4_addresses=["10.0.0.1"], ipv6_addresses=[],
            )
        ],
        installed_packages=[
            InstalledPackage(name="openssl", version="1.1.1w", source="os"),
        ],
    )
    d = snapshot_to_dict(snap)
    assert d["hardware"]["hostname"] == "test-host"
    assert d["installed_packages"][0]["name"] == "openssl"
    assert d["network_interfaces"][0]["ipv4_addresses"] == ["10.0.0.1"]
    # Should be JSON-serializable
    assert json.dumps(d)


# ── Python package scanning ───────────────────────────────────────────────────

def test_collect_python_packages_parses_pip_json():
    mock_pip_output = json.dumps([
        {"name": "requests", "version": "2.31.0"},
        {"name": "anthropic", "version": "0.40.0"},
    ])
    with patch("agent.collector._run", return_value=mock_pip_output):
        pkgs = collect_python_packages()
    names = [p.name for p in pkgs]
    assert "requests" in names
    assert "anthropic" in names
    assert all(p.source in ("pip", "conda") for p in pkgs)


def test_collect_python_packages_handles_empty():
    with patch("agent.collector._run", return_value=""):
        pkgs = collect_python_packages()
    assert pkgs == []


# ── npm scanning ──────────────────────────────────────────────────────────────

def test_collect_npm_packages_from_package_json(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "my-app",
        "dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    with patch("agent.collector._run", return_value=""):
        pkgs = collect_npm_packages(search_roots=[str(tmp_path)])
    names = [p.name for p in pkgs]
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names
    assert all(p.source == "npm" for p in pkgs)


def test_collect_npm_skips_node_modules(tmp_path):
    node_mod = tmp_path / "node_modules" / "some-lib"
    node_mod.mkdir(parents=True)
    (node_mod / "package.json").write_text(
        json.dumps({"name": "should-not-appear", "dependencies": {}})
    )
    real_pkg = tmp_path / "package.json"
    real_pkg.write_text(json.dumps({"dependencies": {"visible-pkg": "1.0.0"}}))
    with patch("agent.collector._run", return_value=""):
        pkgs = collect_npm_packages(search_roots=[str(tmp_path)])
    names = [p.name for p in pkgs]
    assert "visible-pkg" in names
    assert "should-not-appear" not in names


# ── Java JAR scanning ─────────────────────────────────────────────────────────

def test_collect_java_packages_reads_pom_properties(tmp_path):
    import zipfile

    jar_path = tmp_path / "myapp-1.2.3.jar"
    with zipfile.ZipFile(str(jar_path), "w") as zf:
        zf.writestr(
            "META-INF/maven/com.example/myapp/pom.properties",
            "groupId=com.example\nartifactId=myapp\nversion=1.2.3\n",
        )

    pkgs = collect_java_packages(search_roots=[str(tmp_path)])
    assert any(p.name == "com.example:myapp" and p.version == "1.2.3" for p in pkgs)


def test_collect_java_packages_fallback_filename(tmp_path):
    import zipfile

    jar_path = tmp_path / "log4j-1.2.17.jar"
    with zipfile.ZipFile(str(jar_path), "w") as zf:
        zf.writestr("placeholder.txt", "no pom")

    pkgs = collect_java_packages(search_roots=[str(tmp_path)])
    assert any(p.name == "log4j" and p.version == "1.2.17" for p in pkgs)
