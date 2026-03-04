"""
enrichment.py — Claude MCP enrichment pipeline.

Sends batches of raw software inventory to Claude and receives back:
  - Normalized CPE 2.3 identifiers
  - EOL / end-of-support flags
  - Bundled library risk notes
  - Confidence scores

Claude is called via the Anthropic Messages API (used as an MCP-style
reasoning layer).  The prompt is carefully structured so responses are
machine-parseable JSON — no hallucination-prone free text in structured fields.
"""

import json
import logging
import time
from typing import Optional
import anthropic

logger = logging.getLogger(__name__)

# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """
You are a security-focused software asset analyst specializing in CPE (Common
Platform Enumeration) normalization and EOL/EOS (end-of-life / end-of-support)
detection. You have deep knowledge of software supply chains and bundled library
dependencies.

You will receive a JSON array of software packages collected from a host.
For each package you MUST return a JSON object with exactly these fields:

{
  "name": "<original name, unchanged>",
  "version": "<original version, unchanged>",
  "source": "<original source, unchanged>",
  "cpe23": "<CPE 2.3 URI or null if cannot determine>",
  "eol": <true | false | null>,
  "eol_date": "<YYYY-MM-DD or null>",
  "eol_notes": "<brief reason or null>",
  "known_dependencies": [
    {
      "name": "<library name>",
      "version": "<version or 'unknown'>",
      "cpe23": "<CPE 2.3 or null>"
    }
  ],
  "confidence": <0.0–1.0>,
  "notes": "<single sentence of context or null>"
}

Rules:
1. CPE 2.3 format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
2. For EOL: use your training knowledge of vendor support calendars.
   Set eol=null only when genuinely uncertain — do not guess.
3. known_dependencies: list libraries BUNDLED INSIDE this package
   (e.g. OpenSSL inside curl, Log4j inside a fat JAR). Do NOT list
   OS-level transitive deps. Empty array if none known.
4. confidence: your confidence that the CPE and EOL data are correct.
5. Return ONLY a valid JSON array — no preamble, no markdown fences.
""".strip()


# ── Batch enrichment ──────────────────────────────────────────────────────────

def _build_user_message(batch: list[dict]) -> str:
    return json.dumps([
        {"name": p["name"], "version": p["version"], "source": p["source"]}
        for p in batch
    ], indent=2)


def _parse_response(raw: str) -> list[dict]:
    """Strip any accidental markdown fences and parse JSON."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(
            line for line in lines
            if not line.strip().startswith("```")
        )
    return json.loads(text)


def enrich_packages(
    packages: list[dict],
    api_key: str,
    model: str = "claude-sonnet-4-20250514",
    batch_size: int = 40,
    retry_attempts: int = 3,
    retry_delay: float = 5.0,
) -> list[dict]:
    """
    Send packages to Claude in batches and return enriched records.

    packages: list of dicts with keys: name, version, source
    Returns:  same list with additional keys: cpe23, eol, eol_date,
              eol_notes, known_dependencies, confidence, notes
    """
    client = anthropic.Anthropic(api_key=api_key)
    enriched: list[dict] = []

    total = len(packages)
    logger.info("Enriching %d packages in batches of %d…", total, batch_size)

    for i in range(0, total, batch_size):
        batch = packages[i : i + batch_size]
        logger.info(
            "  Batch %d/%d (%d packages)…",
            i // batch_size + 1,
            -(-total // batch_size),
            len(batch),
        )

        for attempt in range(1, retry_attempts + 1):
            try:
                response = client.messages.create(
                    model=model,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    messages=[
                        {"role": "user", "content": _build_user_message(batch)}
                    ],
                )
                raw = response.content[0].text
                results = _parse_response(raw)

                # Merge enrichment back onto original package dicts
                for orig, enrichment in zip(batch, results):
                    merged = {**orig, **enrichment}
                    enriched.append(merged)
                break

            except json.JSONDecodeError as exc:
                logger.warning("Batch %d JSON parse error (attempt %d): %s",
                               i, attempt, exc)
                if attempt == retry_attempts:
                    # Fall back: pass through un-enriched
                    for pkg in batch:
                        enriched.append({
                            **pkg,
                            "cpe23": None, "eol": None, "eol_date": None,
                            "eol_notes": "enrichment_failed",
                            "known_dependencies": [],
                            "confidence": 0.0,
                            "notes": f"Enrichment failed: {exc}",
                        })
                else:
                    time.sleep(retry_delay)

            except anthropic.RateLimitError:
                logger.warning("Rate limited — waiting 60s…")
                time.sleep(60)

            except anthropic.APIError as exc:
                logger.error("Anthropic API error: %s", exc)
                if attempt == retry_attempts:
                    for pkg in batch:
                        enriched.append({**pkg, "cpe23": None, "eol": None,
                                          "eol_date": None, "eol_notes": "api_error",
                                          "known_dependencies": [], "confidence": 0.0,
                                          "notes": str(exc)})
                else:
                    time.sleep(retry_delay * attempt)

    logger.info("Enrichment complete — %d records returned", len(enriched))
    return enriched


# ── EOL summary helper ────────────────────────────────────────────────────────

def summarize_risk(enriched_packages: list[dict]) -> dict:
    """
    Produce a structured risk summary from enriched package list.
    Returns counts and lists for dashboard / CMDB notes field.
    """
    eol_confirmed = [p for p in enriched_packages if p.get("eol") is True]
    no_cpe = [p for p in enriched_packages if not p.get("cpe23")]
    high_confidence = [p for p in enriched_packages if p.get("confidence", 0) >= 0.8]

    all_deps = []
    for p in enriched_packages:
        for dep in p.get("known_dependencies", []):
            all_deps.append({
                "parent": p["name"],
                "parent_version": p["version"],
                **dep,
            })

    return {
        "total_packages": len(enriched_packages),
        "eol_count": len(eol_confirmed),
        "eol_packages": [
            {"name": p["name"], "version": p["version"], "eol_date": p.get("eol_date"),
             "notes": p.get("eol_notes")}
            for p in eol_confirmed
        ],
        "no_cpe_count": len(no_cpe),
        "high_confidence_cpe_count": len(high_confidence),
        "bundled_dependencies_count": len(all_deps),
        "bundled_dependencies": all_deps,
    }
