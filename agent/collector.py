"""
collector.py — Cross-platform hardware, OS, network, and software inventory.

Supports: Windows, Linux, macOS
Called by: agent.py (scheduled task / Ansible / CloudFormation bootstrap)
"""

import os
import sys
import platform
import socket
import subprocess
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class HardwareInfo:
    hostname: str
    fqdn: str
    os_name: str
    os_version: str
    os_build: str
    architecture: str
    cpu_model: str
    cpu_cores_physical: int
    cpu_cores_logical: int
    ram_gb: float
    serial_number: Optional[str]
    manufacturer: Optional[str]
    model: Optional[str]
    bios_version: Optional[str]
    is_virtual: bool
    virtualization_platform: Optional[str]


@dataclass
class NetworkInterface:
    name: str
    mac_address: Optional[str]
    ipv4_addresses: list[str] = field(default_factory=list)
    ipv6_addresses: list[str] = field(default_factory=list)


@dataclass
class InstalledPackage:
    name: str
    version: str
    vendor: Optional[str] = None
    install_date: Optional[str] = None
    source: str = "os"        # os | pip | conda | npm | maven | gradle


@dataclass
class HostSnapshot:
    collected_at: str
    hardware: HardwareInfo
    network_interfaces: list[NetworkInterface]
    installed_packages: list[InstalledPackage]
    agent_version: str = "1.0.0"


# ── Platform helpers ──────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> str:
    """Run a subprocess and return stdout; return '' on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception as exc:
        logger.debug("Command %s failed: %s", cmd, exc)
        return ""


def _is_virtual() -> tuple[bool, Optional[str]]:
    """Detect whether we're running inside a VM or container."""
    indicators = {
        "vmware": "VMware",
        "virtualbox": "VirtualBox",
        "kvm": "KVM",
        "xen": "Xen",
        "hyperv": "Hyper-V",
        "docker": "Docker",
        "lxc": "LXC",
    }
    system = platform.system().lower()

    # Check DMI / system product name (Linux/macOS)
    if system in ("linux", "darwin"):
        product = _run(["sudo", "dmidecode", "-s", "system-product-name"]).lower()
        for key, label in indicators.items():
            if key in product:
                return True, label

    # Check for container environments
    if os.path.exists("/.dockerenv"):
        return True, "Docker"
    if os.path.exists("/run/.containerenv"):
        return True, "Podman/LXC"

    # Windows: check WMI model
    if system == "windows":
        model = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_ComputerSystem).Model"]
        ).lower()
        for key, label in indicators.items():
            if key in model:
                return True, label

    return False, None


# ── Hardware collection ───────────────────────────────────────────────────────

def collect_hardware() -> HardwareInfo:
    system = platform.system()
    is_virtual, virt_platform = _is_virtual()

    hostname = socket.gethostname()
    try:
        fqdn = socket.getfqdn()
    except Exception:
        fqdn = hostname

    # CPU / RAM via psutil (required dependency)
    try:
        import psutil
        cpu_physical = psutil.cpu_count(logical=False) or 1
        cpu_logical = psutil.cpu_count(logical=True) or 1
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except ImportError:
        cpu_physical = cpu_logical = 1
        ram_gb = 0.0
        logger.warning("psutil not available — CPU/RAM info will be incomplete")

    # CPU model
    cpu_model = "Unknown"
    if system == "Linux":
        for line in _run(["cat", "/proc/cpuinfo"]).splitlines():
            if "model name" in line:
                cpu_model = line.split(":", 1)[1].strip()
                break
    elif system == "Darwin":
        cpu_model = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    elif system == "Windows":
        cpu_model = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_Processor).Name"]
        )

    # Hardware identifiers
    serial = manufacturer = model = bios = None
    if system == "Linux":
        serial = _run(["sudo", "dmidecode", "-s", "system-serial-number"])
        manufacturer = _run(["sudo", "dmidecode", "-s", "system-manufacturer"])
        model = _run(["sudo", "dmidecode", "-s", "system-product-name"])
        bios = _run(["sudo", "dmidecode", "-s", "bios-version"])
    elif system == "Darwin":
        serial = _run(
            ["system_profiler", "SPHardwareDataType"]
        )
        # parse serial from output
        for line in (serial or "").splitlines():
            if "Serial Number" in line:
                serial = line.split(":")[1].strip()
                break
        manufacturer = "Apple"
        model = _run(["sysctl", "-n", "hw.model"])
    elif system == "Windows":
        serial = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_BIOS).SerialNumber"]
        )
        manufacturer = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_ComputerSystem).Manufacturer"]
        )
        model = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_ComputerSystem).Model"]
        )
        bios = _run(
            ["powershell", "-Command",
             "(Get-WmiObject Win32_BIOS).SMBIOSBIOSVersion"]
        )

    # OS details
    os_info = platform.uname()
    os_build = os_info.version

    return HardwareInfo(
        hostname=hostname,
        fqdn=fqdn,
        os_name=platform.system(),
        os_version=platform.version(),
        os_build=os_build,
        architecture=platform.machine(),
        cpu_model=cpu_model,
        cpu_cores_physical=cpu_physical,
        cpu_cores_logical=cpu_logical,
        ram_gb=ram_gb,
        serial_number=serial or None,
        manufacturer=manufacturer or None,
        model=model or None,
        bios_version=bios or None,
        is_virtual=is_virtual,
        virtualization_platform=virt_platform,
    )


# ── Network collection ────────────────────────────────────────────────────────

def collect_network() -> list[NetworkInterface]:
    interfaces = []
    try:
        import psutil
        for name, addrs in psutil.net_if_addrs().items():
            iface = NetworkInterface(name=name, mac_address=None)
            for addr in addrs:
                import psutil as _ps
                if addr.family == _ps.AF_LINK if hasattr(_ps, "AF_LINK") else -1:
                    iface.mac_address = addr.address
                elif addr.family == socket.AF_INET:
                    iface.ipv4_addresses.append(addr.address)
                elif addr.family == socket.AF_INET6:
                    iface.ipv6_addresses.append(addr.address)
            if iface.ipv4_addresses or iface.mac_address:
                interfaces.append(iface)
    except Exception as exc:
        logger.warning("Network collection failed: %s", exc)
    return interfaces


# ── OS-level package collection ───────────────────────────────────────────────

def _collect_windows_software() -> list[InstalledPackage]:
    pkgs = []
    ps_cmd = r"""
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    ConvertTo-Json -Compress
    """
    raw = _run(["powershell", "-Command", ps_cmd])
    if not raw:
        return pkgs
    try:
        items = json.loads(raw)
        if isinstance(items, dict):
            items = [items]
        for item in items:
            name = item.get("DisplayName")
            if not name:
                continue
            pkgs.append(InstalledPackage(
                name=name,
                version=item.get("DisplayVersion") or "unknown",
                vendor=item.get("Publisher"),
                install_date=item.get("InstallDate"),
                source="os",
            ))
    except json.JSONDecodeError as exc:
        logger.warning("Windows registry parse error: %s", exc)
    return pkgs


def _collect_linux_software() -> list[InstalledPackage]:
    pkgs = []
    # Try dpkg first (Debian/Ubuntu), then rpm
    dpkg_out = _run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\n"]
    )
    if dpkg_out:
        for line in dpkg_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                pkgs.append(InstalledPackage(
                    name=parts[0], version=parts[1],
                    vendor=parts[2] if len(parts) > 2 else None,
                    source="os",
                ))
        return pkgs

    rpm_out = _run(
        ["rpm", "-qa", "--queryformat",
         "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"]
    )
    if rpm_out:
        for line in rpm_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                pkgs.append(InstalledPackage(
                    name=parts[0], version=parts[1],
                    vendor=parts[2] if len(parts) > 2 else None,
                    source="os",
                ))
    return pkgs


def _collect_macos_software() -> list[InstalledPackage]:
    pkgs = []
    raw = _run(["system_profiler", "SPApplicationsDataType", "-json"])
    if not raw:
        return pkgs
    try:
        data = json.loads(raw)
        apps = data.get("SPApplicationsDataType", [])
        for app in apps:
            pkgs.append(InstalledPackage(
                name=app.get("_name", "Unknown"),
                version=app.get("version", "unknown"),
                vendor=app.get("obtained_from"),
                source="os",
            ))
    except json.JSONDecodeError as exc:
        logger.warning("macOS app parse error: %s", exc)
    return pkgs


def collect_os_software() -> list[InstalledPackage]:
    system = platform.system()
    if system == "Windows":
        return _collect_windows_software()
    elif system == "Linux":
        return _collect_linux_software()
    elif system == "Darwin":
        return _collect_macos_software()
    return []


# ── Dependency / ecosystem scanning ──────────────────────────────────────────

def collect_python_packages() -> list[InstalledPackage]:
    """Enumerate pip-installed packages from all discoverable Python envs."""
    pkgs = []
    raw = _run([sys.executable, "-m", "pip", "list", "--format=json"])
    if raw:
        try:
            for item in json.loads(raw):
                pkgs.append(InstalledPackage(
                    name=item["name"],
                    version=item["version"],
                    source="pip",
                ))
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("pip list parse error: %s", exc)

    # Also check conda if available
    conda_out = _run(["conda", "list", "--json"])
    if conda_out:
        try:
            for item in json.loads(conda_out):
                pkgs.append(InstalledPackage(
                    name=item["name"],
                    version=item["version"],
                    source="conda",
                ))
        except (json.JSONDecodeError, KeyError):
            pass
    return pkgs


def collect_npm_packages(search_roots: Optional[list[str]] = None) -> list[InstalledPackage]:
    """
    Find npm package.json files under search_roots and extract dependencies.
    Defaults to common project locations.
    """
    pkgs = []
    if search_roots is None:
        home = os.path.expanduser("~")
        search_roots = ["/opt", "/srv", "/var/www", "/app", home]
        if platform.system() == "Windows":
            search_roots = [
                os.environ.get("APPDATA", ""),
                r"C:\inetpub",
                r"C:\apps",
                os.path.expanduser("~"),
            ]

    visited_package_jsons = set()

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Skip node_modules to avoid enormous recursive traversal
            dirnames[:] = [d for d in dirnames if d != "node_modules"]
            depth = dirpath.replace(root, "").count(os.sep)
            if depth > 8:
                dirnames.clear()
                continue
            if "package.json" in filenames:
                pj_path = os.path.join(dirpath, "package.json")
                if pj_path in visited_package_jsons:
                    continue
                visited_package_jsons.add(pj_path)
                try:
                    with open(pj_path, "r", encoding="utf-8", errors="ignore") as fh:
                        data = json.load(fh)
                    for dep_key in ("dependencies", "devDependencies",
                                    "peerDependencies", "optionalDependencies"):
                        for name, version in data.get(dep_key, {}).items():
                            pkgs.append(InstalledPackage(
                                name=name,
                                version=version.lstrip("^~>=<") or "unknown",
                                source="npm",
                            ))
                except Exception as exc:
                    logger.debug("Could not parse %s: %s", pj_path, exc)

    # Also query global npm registry
    global_npm = _run(["npm", "list", "-g", "--json", "--depth=0"])
    if global_npm:
        try:
            data = json.loads(global_npm)
            for name, info in data.get("dependencies", {}).items():
                pkgs.append(InstalledPackage(
                    name=name,
                    version=info.get("version", "unknown"),
                    source="npm",
                ))
        except json.JSONDecodeError:
            pass

    return pkgs


def collect_java_packages(search_roots: Optional[list[str]] = None) -> list[InstalledPackage]:
    """
    Walk filesystem for JAR/WAR/EAR files and extract Maven metadata
    from META-INF/maven/**/pom.properties to identify groupId/artifactId/version.
    Falls back to filename parsing if no pom.properties found.
    """
    import zipfile
    import re

    pkgs = []
    if search_roots is None:
        search_roots = ["/opt", "/srv", "/var", "/app", "/usr/share/java",
                        os.path.expanduser("~")]
        if platform.system() == "Windows":
            search_roots = [
                r"C:\Program Files",
                r"C:\Program Files (x86)",
                r"C:\apps",
                os.path.expanduser("~"),
            ]

    jar_pattern = re.compile(r"\.(?:jar|war|ear)$", re.IGNORECASE)
    version_from_name = re.compile(
        r"^(.+?)[-_](\d+[\d.\-_a-zA-Z]*)\.(?:jar|war|ear)$", re.IGNORECASE
    )
    seen_jars: set[str] = set()

    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            depth = dirpath.replace(root, "").count(os.sep)
            if depth > 10:
                dirnames.clear()
                continue
            for fname in filenames:
                if not jar_pattern.search(fname):
                    continue
                jar_path = os.path.join(dirpath, fname)
                if jar_path in seen_jars:
                    continue
                seen_jars.add(jar_path)

                found_pom = False
                try:
                    with zipfile.ZipFile(jar_path, "r") as zf:
                        pom_files = [
                            n for n in zf.namelist()
                            if n.startswith("META-INF/maven") and n.endswith("pom.properties")
                        ]
                        for pom_path in pom_files:
                            try:
                                pom_data = zf.read(pom_path).decode("utf-8", errors="ignore")
                                props = {}
                                for line in pom_data.splitlines():
                                    if "=" in line and not line.startswith("#"):
                                        k, _, v = line.partition("=")
                                        props[k.strip()] = v.strip()
                                group_id = props.get("groupId", "")
                                artifact_id = props.get("artifactId", fname)
                                version = props.get("version", "unknown")
                                name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                                pkgs.append(InstalledPackage(
                                    name=name,
                                    version=version,
                                    source="maven",
                                ))
                                found_pom = True
                            except Exception:
                                pass
                except Exception as exc:
                    logger.debug("Could not open JAR %s: %s", jar_path, exc)
                    continue

                # Fallback: parse version from filename
                if not found_pom:
                    m = version_from_name.match(fname)
                    if m:
                        pkgs.append(InstalledPackage(
                            name=m.group(1),
                            version=m.group(2),
                            source="maven",
                        ))
                    else:
                        pkgs.append(InstalledPackage(
                            name=fname,
                            version="unknown",
                            source="maven",
                        ))

    return pkgs


# ── Main snapshot builder ─────────────────────────────────────────────────────

def collect_snapshot(config: dict) -> HostSnapshot:
    """
    Collect a full host snapshot.  config keys used:
      scan_java   (bool, default True)
      scan_npm    (bool, default True)
      scan_python (bool, default True)
      java_search_roots  (list[str], optional)
      npm_search_roots   (list[str], optional)
    """
    logger.info("Collecting hardware and OS info…")
    hardware = collect_hardware()

    logger.info("Collecting network interfaces…")
    network = collect_network()

    logger.info("Collecting OS-level software…")
    packages = collect_os_software()

    if config.get("scan_python", True):
        logger.info("Scanning Python packages…")
        packages.extend(collect_python_packages())

    if config.get("scan_npm", True):
        logger.info("Scanning npm packages…")
        packages.extend(collect_npm_packages(config.get("npm_search_roots")))

    if config.get("scan_java", True):
        logger.info("Scanning Java JARs…")
        packages.extend(collect_java_packages(config.get("java_search_roots")))

    return HostSnapshot(
        collected_at=datetime.now(timezone.utc).isoformat(),
        hardware=hardware,
        network_interfaces=network,
        installed_packages=packages,
    )


def snapshot_to_dict(snapshot: HostSnapshot) -> dict:
    return asdict(snapshot)
