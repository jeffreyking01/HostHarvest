"""
cmdb_clients.py — Snipe-IT and GLPI API clients.

Authentication is flexible:
  - Config file (config.yaml)
  - Environment variables  (SNIPEIT_TOKEN, GLPI_APP_TOKEN, GLPI_USER_TOKEN)
  - Injected at runtime (Ansible, CloudFormation)

Both clients implement upsert semantics:
  search first → create if missing, update if found.
"""

import logging
import os
import requests
from typing import Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_secret(config_value: Optional[str], env_var: str) -> str:
    """Resolve a secret from config or environment variable."""
    val = config_value or os.environ.get(env_var, "")
    if not val:
        raise ValueError(
            f"Missing credential: set config value or env var {env_var}"
        )
    return val


# ── Snipe-IT client ───────────────────────────────────────────────────────────

class SnipeITClient:
    """
    Wraps the Snipe-IT v1 REST API.
    Manages: Assets (hardware), Asset Models, Manufacturers, Software Licenses.

    Docs: https://snipe-it.readme.io/reference
    """

    def __init__(self, base_url: str, api_token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        token = _get_secret(api_token, "SNIPEIT_TOKEN")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        })

    def _get(self, path: str, params: dict = None) -> dict:
        resp = self.session.get(f"{self.base_url}/api/v1{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict:
        resp = self.session.post(f"{self.base_url}/api/v1{path}", json=data)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, data: dict) -> dict:
        resp = self.session.patch(f"{self.base_url}/api/v1{path}", json=data)
        resp.raise_for_status()
        return resp.json()

    # ── Manufacturers ──

    def find_or_create_manufacturer(self, name: str) -> int:
        """Return manufacturer ID, creating if necessary."""
        results = self._get("/manufacturers", params={"search": name, "limit": 5})
        for row in results.get("rows", []):
            if row["name"].lower() == name.lower():
                return row["id"]
        created = self._post("/manufacturers", {"name": name})
        return created["payload"]["id"]

    # ── Asset Models ──

    def find_or_create_model(self, model_name: str, manufacturer_id: int,
                              category_id: int = 1) -> int:
        """Return asset model ID."""
        results = self._get("/models", params={"search": model_name, "limit": 5})
        for row in results.get("rows", []):
            if row["name"].lower() == model_name.lower():
                return row["id"]
        created = self._post("/models", {
            "name": model_name,
            "manufacturer_id": manufacturer_id,
            "category_id": category_id,
        })
        return created["payload"]["id"]

    # ── Assets (hardware) ──

    def find_asset_by_serial(self, serial: str) -> Optional[dict]:
        results = self._get("/hardware", params={"search": serial, "limit": 5})
        for row in results.get("rows", []):
            if row.get("serial") == serial:
                return row
        return None

    def find_asset_by_name(self, name: str) -> Optional[dict]:
        results = self._get("/hardware", params={"search": name, "limit": 5})
        for row in results.get("rows", []):
            if row.get("name", "").lower() == name.lower():
                return row
        return None

    def upsert_asset(self, hardware: dict, risk_summary: dict) -> dict:
        """
        Create or update a hardware asset in Snipe-IT.
        hardware: from collector.HardwareInfo (as dict)
        risk_summary: from enrichment.summarize_risk()
        """
        # Resolve manufacturer + model
        manufacturer_id = None
        model_id = None
        if hardware.get("manufacturer"):
            manufacturer_id = self.find_or_create_manufacturer(hardware["manufacturer"])
        if hardware.get("model") and manufacturer_id:
            model_id = self.find_or_create_model(hardware["model"], manufacturer_id)

        notes = (
            f"EOL packages: {risk_summary['eol_count']} | "
            f"Bundled deps: {risk_summary['bundled_dependencies_count']} | "
            f"Total scanned: {risk_summary['total_packages']} | "
            f"Last agent run: {datetime.now(timezone.utc).isoformat()}"
        )

        payload = {
            "name": hardware["hostname"],
            "serial": hardware.get("serial_number") or "",
            "notes": notes,
            "status_id": 1,    # Ready to Deploy (default)
            "_snipeit_fqdn": hardware.get("fqdn", ""),
            "_snipeit_os": f"{hardware['os_name']} {hardware['os_version']}",
            "_snipeit_cpu": hardware.get("cpu_model", ""),
            "_snipeit_ram_gb": str(hardware.get("ram_gb", "")),
            "_snipeit_is_virtual": str(hardware.get("is_virtual", "")),
            "_snipeit_virt_platform": hardware.get("virtualization_platform") or "",
        }

        if model_id:
            payload["model_id"] = model_id

        # Upsert by serial, fall back to hostname
        existing = None
        if hardware.get("serial_number"):
            existing = self.find_asset_by_serial(hardware["serial_number"])
        if not existing:
            existing = self.find_asset_by_name(hardware["hostname"])

        if existing:
            logger.info("Updating Snipe-IT asset id=%s (%s)",
                        existing["id"], hardware["hostname"])
            return self._patch(f"/hardware/{existing['id']}", payload)
        else:
            logger.info("Creating Snipe-IT asset: %s", hardware["hostname"])
            return self._post("/hardware", payload)


# ── GLPI client ───────────────────────────────────────────────────────────────

class GLPIClient:
    """
    Wraps the GLPI REST API.
    Manages: Computers (assets), Software, SoftwareVersions, Computer↔Software links.

    GLPI uses a session token obtained by init_session().
    App token + user token auth is recommended for automated agents.

    Docs: https://github.com/glpi-project/glpi/blob/main/apirest.md
    """

    def __init__(
        self,
        base_url: str,
        app_token: Optional[str] = None,
        user_token: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/") + "/apirest.php"
        self.app_token = _get_secret(app_token, "GLPI_APP_TOKEN")
        self.user_token = _get_secret(user_token, "GLPI_USER_TOKEN")
        self.session_token: Optional[str] = None
        self.session = requests.Session()

    def init_session(self):
        """Exchange user token for a session token."""
        resp = self.session.get(
            f"{self.base_url}/initSession",
            headers={
                "App-Token": self.app_token,
                "Authorization": f"user_token {self.user_token}",
            },
        )
        resp.raise_for_status()
        self.session_token = resp.json()["session_token"]
        self.session.headers.update({
            "App-Token": self.app_token,
            "Session-Token": self.session_token,
            "Content-Type": "application/json",
        })
        logger.debug("GLPI session initialized")

    def kill_session(self):
        if self.session_token:
            self.session.get(f"{self.base_url}/killSession")
            self.session_token = None

    def __enter__(self):
        self.init_session()
        return self

    def __exit__(self, *_):
        self.kill_session()

    def _get(self, path: str, params: dict = None) -> dict:
        resp = self.session.get(f"{self.base_url}{path}", params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, data: dict) -> dict:
        resp = self.session.post(f"{self.base_url}{path}", json={"input": data})
        resp.raise_for_status()
        return resp.json()

    def _put(self, path: str, data: dict) -> dict:
        resp = self.session.put(f"{self.base_url}{path}", json={"input": data})
        resp.raise_for_status()
        return resp.json()

    # ── Computer (asset) ──

    def search_computer(self, name: str) -> Optional[dict]:
        """Search for a Computer by name. Returns first match or None."""
        results = self._get("/search/Computer", params={
            "criteria[0][field]": "1",         # field 1 = name
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": name,
            "forcedisplay[0]": "1",
            "forcedisplay[1]": "2",             # ID
        })
        items = results.get("data", [])
        return items[0] if items else None

    def upsert_computer(self, hardware: dict) -> int:
        """Create or update a Computer record. Returns GLPI item ID."""
        payload = {
            "name": hardware["hostname"],
            "comment": (
                f"FQDN: {hardware.get('fqdn', '')} | "
                f"OS: {hardware['os_name']} {hardware['os_version']} | "
                f"CPU: {hardware.get('cpu_model', '')} | "
                f"RAM: {hardware.get('ram_gb', '')} GB | "
                f"Serial: {hardware.get('serial_number', '')} | "
                f"Virtual: {hardware.get('is_virtual', False)}"
            ),
        }

        existing = self.search_computer(hardware["hostname"])
        if existing:
            glpi_id = existing.get("2") or existing.get("id")
            logger.info("Updating GLPI Computer id=%s (%s)", glpi_id, hardware["hostname"])
            self._put(f"/Computer/{glpi_id}", payload)
            return int(glpi_id)
        else:
            logger.info("Creating GLPI Computer: %s", hardware["hostname"])
            result = self._post("/Computer", payload)
            return int(result.get("id", result[0].get("id")))

    # ── Software ──

    def find_or_create_software(self, name: str) -> int:
        """Return Software item ID."""
        results = self._get("/search/Software", params={
            "criteria[0][field]": "1",
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": name,
            "forcedisplay[0]": "2",
        })
        items = results.get("data", [])
        if items:
            return int(items[0].get("2") or items[0].get("id"))
        result = self._post("/Software", {"name": name})
        return int(result.get("id", result[0].get("id")))

    def find_or_create_software_version(
        self, software_id: int, version: str, cpe23: Optional[str] = None
    ) -> int:
        """Return SoftwareVersion item ID."""
        results = self._get("/search/SoftwareVersion", params={
            "criteria[0][field]": "2",   # softwares_id
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": str(software_id),
            "criteria[1][field]": "5",   # version name
            "criteria[1][searchtype]": "equals",
            "criteria[1][value]": version,
            "forcedisplay[0]": "2",
        })
        items = results.get("data", [])
        if items:
            return int(items[0].get("2") or items[0].get("id"))
        payload: dict = {"softwares_id": software_id, "name": version}
        if cpe23:
            payload["comment"] = f"CPE: {cpe23}"
        result = self._post("/SoftwareVersion", payload)
        return int(result.get("id", result[0].get("id")))

    def link_software_to_computer(
        self, computer_id: int, software_version_id: int
    ):
        """Create Computer_SoftwareVersion link if it doesn't exist."""
        # Check existing
        results = self._get("/search/Computer_SoftwareVersion", params={
            "criteria[0][field]": "3",   # computers_id
            "criteria[0][searchtype]": "equals",
            "criteria[0][value]": str(computer_id),
            "criteria[1][field]": "5",   # softwareversions_id
            "criteria[1][searchtype]": "equals",
            "criteria[1][value]": str(software_version_id),
            "forcedisplay[0]": "2",
        })
        if results.get("data"):
            return   # already linked
        self._post("/Computer_SoftwareVersion", {
            "computers_id": computer_id,
            "softwareversions_id": software_version_id,
        })

    def sync_software_inventory(
        self, computer_id: int, enriched_packages: list[dict]
    ):
        """
        Full software sync for a computer:
        1. Find/create each Software + SoftwareVersion
        2. Link to Computer
        3. Tag EOL packages in version comment
        """
        total = len(enriched_packages)
        logger.info("Syncing %d packages to GLPI computer_id=%d…", total, computer_id)
        for i, pkg in enumerate(enriched_packages, 1):
            if i % 50 == 0:
                logger.info("  %d/%d packages synced…", i, total)
            try:
                sw_id = self.find_or_create_software(pkg["name"])
                version_str = pkg["version"]

                # Annotate version with EOL / CPE data
                comment_parts = []
                if pkg.get("cpe23"):
                    comment_parts.append(f"CPE: {pkg['cpe23']}")
                if pkg.get("eol"):
                    eol_note = f"EOL: {pkg.get('eol_date', 'date unknown')}"
                    if pkg.get("eol_notes"):
                        eol_note += f" — {pkg['eol_notes']}"
                    comment_parts.append(eol_note)
                if pkg.get("known_dependencies"):
                    dep_names = ", ".join(
                        d["name"] for d in pkg["known_dependencies"]
                    )
                    comment_parts.append(f"Bundled deps: {dep_names}")
                comment = " | ".join(comment_parts) or None

                sv_id = self.find_or_create_software_version(
                    sw_id, version_str, cpe23=comment
                )
                self.link_software_to_computer(computer_id, sv_id)

            except Exception as exc:
                logger.warning("Failed to sync package %s: %s", pkg.get("name"), exc)

        logger.info("GLPI software sync complete for computer_id=%d", computer_id)
