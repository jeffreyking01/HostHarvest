"""
ironfist_client.py — IronFist CMDB integration for HostHarvest.

Slots into the existing HostHarvest pipeline alongside Snipe-IT and GLPI.
POSTs the host snapshot to the IronFist /api/assets/ingest endpoint.

Authentication: Bearer token (set IRONFIST_TOKEN env var or config.yaml)

Usage in agent.py:
    from cmdb.ironfist_client import IronFistClient
    ...
    ironfist = IronFistClient(
        base_url=cfg["base_url"],
        token=cfg.get("token"),
    )
    ironfist.ingest(snapshot_dict, enriched_packages)
"""

import logging
import os
import socket
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class IronFistClient:
    """
    Sends HostHarvest snapshot data to the IronFist asset ingest endpoint.

    Maps HostHarvest's rich snapshot schema onto IronFist's AssetIngest schema:
      - hardware   → ip_address, hostname, fqdn, os_name, os_version
      - packages   → raw_data (stored for future CVE cross-reference)
      - enrichment → tags (eol_count, cpe_count, bundled_deps)
    """

    def __init__(self, base_url: str, token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token    = token or os.environ.get("IRONFIST_TOKEN", "")
        if not self.token:
            raise ValueError(
                "IronFist token is required. "
                "Set IRONFIST_TOKEN env var or ironfist.token in config.yaml"
            )
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type":  "application/json",
        })

    def ingest(self, snapshot: dict, enriched_packages: list[dict]) -> dict:
        """
        Main entry point. Sends asset data to IronFist.

        Args:
            snapshot:           Output of snapshot_to_dict() from collector.py
            enriched_packages:  Package list after Claude enrichment step

        Returns:
            IronFist API response dict with asset_id and action (created/updated)
        """
        hardware   = snapshot.get("hardware", {})
        network    = snapshot.get("network_interfaces", [])

        # Pick the best primary IP — first non-loopback IPv4 address
        primary_ip = _pick_primary_ip(network) or hardware.get("hostname", "unknown")

        # Build tags from enrichment data
        eol_packages = [
            p["name"] for p in enriched_packages
            if p.get("eol")
        ]
        cpe_count = sum(1 for p in enriched_packages if p.get("cpe23"))

        payload = {
            "ip_address":   primary_ip,
            "hostname":     hardware.get("hostname"),
            "fqdn":         hardware.get("fqdn"),
            "os_name":      hardware.get("os_name"),
            "os_version":   _format_os_version(hardware),
            "system_owner": None,        # Set via IronFist UI or extend config
            "fisma_boundary": None,      # Set via IronFist UI or extend config
            "criticality":  "MEDIUM",   # Default; override in config
            "agent_version": snapshot.get("agent_version", "1.0.0"),
            "tags": {
                "architecture":          hardware.get("architecture"),
                "cpu_model":             hardware.get("cpu_model"),
                "cpu_cores_logical":     hardware.get("cpu_cores_logical"),
                "ram_gb":                hardware.get("ram_gb"),
                "manufacturer":          hardware.get("manufacturer"),
                "model":                 hardware.get("model"),
                "serial_number":         hardware.get("serial_number"),
                "is_virtual":            hardware.get("is_virtual"),
                "virtualization_platform": hardware.get("virtualization_platform"),
                "bios_version":          hardware.get("bios_version"),
                "collected_at":          snapshot.get("collected_at"),
                # Enrichment summary
                "package_count":         len(enriched_packages),
                "eol_package_count":     len(eol_packages),
                "eol_packages":          eol_packages[:20],  # cap for storage
                "cpe_matched_count":     cpe_count,
                # Network summary
                "network_interfaces":    _summarize_network(network),
            },
            "raw_data": {
                # Store full package list for future CVE cross-reference
                # IronFist normalization engine will use this in Phase 3
                "packages": [
                    {
                        "name":    p.get("name"),
                        "version": p.get("version"),
                        "source":  p.get("source"),
                        "cpe23":   p.get("cpe23"),
                        "eol":     p.get("eol"),
                        "eol_date": p.get("eol_date"),
                    }
                    for p in enriched_packages
                ],
                "hardware": hardware,
            },
        }

        logger.info(
            "Sending asset to IronFist: hostname=%s ip=%s packages=%d",
            payload["hostname"], payload["ip_address"], len(enriched_packages),
        )

        try:
            resp = self.session.post(
                f"{self.base_url}/api/assets/ingest",
                json=payload,
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                "IronFist ingest complete: asset_id=%s action=%s",
                result.get("asset_id"), result.get("action"),
            )
            return result

        except requests.HTTPError as e:
            logger.error("IronFist HTTP error: %s — %s", e, e.response.text if e.response else "")
            raise
        except requests.ConnectionError:
            logger.error(
                "IronFist connection failed — is the server running at %s?",
                self.base_url,
            )
            raise


# ── Helpers ────────────────────────────────────────────────────────────────────

def _pick_primary_ip(network_interfaces: list[dict]) -> Optional[str]:
    """
    Select the best primary IPv4 address from network interfaces.
    Priority: non-loopback, non-link-local, non-Docker bridge.
    """
    skip_prefixes = ("127.", "169.254.", "172.17.")   # loopback, link-local, Docker

    candidates = []
    for iface in network_interfaces:
        for ip in iface.get("ipv4_addresses", []):
            if not any(ip.startswith(p) for p in skip_prefixes):
                candidates.append(ip)

    # Prefer RFC1918 private addresses (likely the real host IP)
    for ip in candidates:
        if ip.startswith(("10.", "192.168.")) or (
            ip.startswith("172.") and
            16 <= int(ip.split(".")[1]) <= 31
        ):
            return ip

    return candidates[0] if candidates else None


def _format_os_version(hardware: dict) -> str:
    """Build a clean OS version string."""
    os_name    = hardware.get("os_name", "")
    os_version = hardware.get("os_version", "")
    # Truncate very long Windows version strings
    if len(os_version) > 80:
        os_version = os_version[:80] + "..."
    return os_version


def _summarize_network(network_interfaces: list[dict]) -> list[dict]:
    """Return a compact network summary for tagging."""
    return [
        {
            "name": iface.get("name"),
            "mac":  iface.get("mac_address"),
            "ipv4": iface.get("ipv4_addresses", []),
        }
        for iface in network_interfaces
        if iface.get("ipv4_addresses") or iface.get("mac_address")
    ]
