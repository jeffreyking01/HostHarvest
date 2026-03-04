#!/usr/bin/env python3
"""
agent.py — CMDB Asset Discovery Agent
======================================

Entry point for the VulnOps CMDB population agent.

Usage:
    python agent.py                         # uses config.yaml in same dir
    python agent.py --config /path/to/cfg  # explicit config path
    python agent.py --dry-run              # collect + enrich, no CMDB writes
    python agent.py --no-enrich            # skip Claude enrichment

Triggered by:
    - Cron / Windows Scheduled Task (periodic check-in)
    - Ansible cmdb-agent role (first-run on provision)
    - CloudFormation UserData bootstrap (EC2 instance creation)
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import yaml

# Allow running from repo root or agent/ subdirectory
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.collector import collect_snapshot, snapshot_to_dict
from enrichment.enrichment import enrich_packages, summarize_risk
from cmdb.cmdb_clients import SnipeITClient, GLPIClient

# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO", log_file: str = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=handlers,
    )


# ── Config loading ────────────────────────────────────────────────────────────

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config.yaml"


def load_config(path: str = None) -> dict:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r") as fh:
        cfg = yaml.safe_load(fh)
    # Allow environment variables to override config secrets
    if "anthropic" in cfg:
        cfg["anthropic"]["api_key"] = (
            os.environ.get("ANTHROPIC_API_KEY") or cfg["anthropic"].get("api_key", "")
        )
    if "snipeit" in cfg:
        cfg["snipeit"]["api_token"] = (
            os.environ.get("SNIPEIT_TOKEN") or cfg["snipeit"].get("api_token", "")
        )
    if "glpi" in cfg:
        cfg["glpi"]["app_token"] = (
            os.environ.get("GLPI_APP_TOKEN") or cfg["glpi"].get("app_token", "")
        )
        cfg["glpi"]["user_token"] = (
            os.environ.get("GLPI_USER_TOKEN") or cfg["glpi"].get("user_token", "")
        )
    return cfg


# ── Core pipeline ─────────────────────────────────────────────────────────────

def run(config: dict, dry_run: bool = False, skip_enrich: bool = False):
    log = logging.getLogger("agent")

    # ── Step 1: Collect ──────────────────────────────────────────────────────
    log.info("=== Step 1: Collecting host inventory ===")
    scan_cfg = config.get("scan", {})
    snapshot = collect_snapshot(scan_cfg)
    snapshot_dict = snapshot_to_dict(snapshot)

    log.info(
        "Collected: hostname=%s, OS=%s %s, packages=%d",
        snapshot.hardware.hostname,
        snapshot.hardware.os_name,
        snapshot.hardware.os_version,
        len(snapshot.installed_packages),
    )

    # Optionally write raw snapshot to disk (useful for debugging / audit trail)
    if config.get("output", {}).get("save_raw_snapshot"):
        raw_path = config["output"].get("raw_snapshot_path", "/tmp/cmdb_snapshot.json")
        with open(raw_path, "w") as fh:
            json.dump(snapshot_dict, fh, indent=2, default=str)
        log.info("Raw snapshot saved to %s", raw_path)

    # ── Step 2: Enrich via Claude ─────────────────────────────────────────────
    enriched_packages = snapshot_dict["installed_packages"]

    if not skip_enrich:
        log.info("=== Step 2: Enriching via Claude MCP ===")
        anthropic_cfg = config.get("anthropic", {})
        api_key = anthropic_cfg.get("api_key", "")
        if not api_key:
            log.warning("No Anthropic API key — skipping enrichment")
        else:
            enriched_packages = enrich_packages(
                packages=enriched_packages,
                api_key=api_key,
                model=anthropic_cfg.get("model", "claude-sonnet-4-20250514"),
                batch_size=anthropic_cfg.get("batch_size", 40),
            )
    else:
        log.info("=== Step 2: Enrichment skipped (--no-enrich) ===")

    risk_summary = summarize_risk(enriched_packages)
    log.info(
        "Risk summary: total=%d, EOL=%d, bundled_deps=%d, no_cpe=%d",
        risk_summary["total_packages"],
        risk_summary["eol_count"],
        risk_summary["bundled_dependencies_count"],
        risk_summary["no_cpe_count"],
    )

    if dry_run:
        log.info("=== Dry run — skipping CMDB writes ===")
        print(json.dumps(risk_summary, indent=2))
        return

    # ── Step 3: Push to Snipe-IT ──────────────────────────────────────────────
    snipeit_cfg = config.get("snipeit", {})
    if snipeit_cfg.get("enabled", True):
        log.info("=== Step 3a: Pushing hardware to Snipe-IT ===")
        try:
            snipeit = SnipeITClient(
                base_url=snipeit_cfg["base_url"],
                api_token=snipeit_cfg.get("api_token"),
            )
            snipeit.upsert_asset(snapshot_dict["hardware"], risk_summary)
            log.info("Snipe-IT asset upserted successfully")
        except Exception as exc:
            log.error("Snipe-IT push failed: %s", exc)
    else:
        log.info("Snipe-IT push disabled in config")

    # ── Step 4: Push to GLPI ──────────────────────────────────────────────────
    glpi_cfg = config.get("glpi", {})
    if glpi_cfg.get("enabled", True):
        log.info("=== Step 3b: Pushing software inventory to GLPI ===")
        try:
            with GLPIClient(
                base_url=glpi_cfg["base_url"],
                app_token=glpi_cfg.get("app_token"),
                user_token=glpi_cfg.get("user_token"),
            ) as glpi:
                computer_id = glpi.upsert_computer(snapshot_dict["hardware"])
                glpi.sync_software_inventory(computer_id, enriched_packages)
            log.info("GLPI sync complete")
        except Exception as exc:
            log.error("GLPI push failed: %s", exc)
    else:
        log.info("GLPI push disabled in config")

    log.info("=== Agent run complete ===")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VulnOps CMDB Asset Discovery Agent"
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config.yaml (default: ../config.yaml relative to agent.py)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and enrich but do not write to Snipe-IT or GLPI",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip Claude enrichment step",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Optional path to write logs to file",
    )
    args = parser.parse_args()

    setup_logging(args.log_level, args.log_file)

    try:
        config = load_config(args.config)
    except FileNotFoundError as exc:
        logging.error(str(exc))
        sys.exit(1)

    run(config, dry_run=args.dry_run, skip_enrich=args.no_enrich)


if __name__ == "__main__":
    main()
