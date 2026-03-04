# VulnOps CMDB Agent

Cross-platform host inventory agent that populates **Snipe-IT** (hardware assets)
and **GLPI** (software inventory) using **Claude** as an enrichment layer for
CPE normalization, EOL detection, and bundled dependency identification.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Host (Windows / Linux / macOS)                             │
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │  OS packages │   │  Java JARs   │   │  npm / pip     │  │
│  │  (dpkg/rpm/  │   │  (pom.props  │   │  (package.json │  │
│  │   registry)  │   │   + filename)│   │   pip list)    │  │
│  └──────┬───────┘   └──────┬───────┘   └───────┬────────┘  │
│         └──────────────────┴───────────────────┘           │
│                             │                               │
│                    collector.py                             │
│                    HostSnapshot                             │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  enrichment.py                │
              │                               │
              │  Claude (claude-sonnet-4)     │
              │  • CPE 2.3 normalization      │
              │  • EOL / EOS detection        │
              │  • Bundled library mapping    │
              │  • Confidence scoring         │
              └───────────────┬───────────────┘
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
   ┌─────────────────────┐      ┌─────────────────────────┐
   │  Snipe-IT           │      │  GLPI                   │
   │  Hardware asset     │      │  Software inventory     │
   │  Manufacturer       │      │  SoftwareVersion        │
   │  Model              │      │  Computer↔Software link │
   │  Risk notes         │      │  CPE / EOL in comments  │
   └─────────────────────┘      └─────────────────────────┘
```

---

## Repository Structure

```
cmdb-agent/
├── agent/
│   ├── agent.py          # Entry point — orchestrates collect → enrich → push
│   └── collector.py      # Cross-platform hardware, OS, network, dep scanning
├── enrichment/
│   └── enrichment.py     # Claude MCP enrichment (CPE, EOL, deps)
├── cmdb/
│   └── cmdb_clients.py   # Snipe-IT and GLPI API clients
├── deploy/
│   ├── ansible/
│   │   └── roles/cmdb-agent/
│   │       ├── tasks/main.yml          # Ansible role
│   │       └── templates/config.yaml.j2
│   └── cloudformation/
│       └── ec2-bootstrap.yaml          # EC2 UserData + IAM role
├── tests/
│   └── test_collector.py
├── config.yaml           # Agent configuration (see comments inside)
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Prerequisites

- Python 3.10+
- `pip3 install -r requirements.txt`
- Snipe-IT instance with API enabled
- GLPI instance with REST API enabled
- Anthropic API key

### 2. Configure

```bash
cp config.yaml config.local.yaml
# Edit config.local.yaml — set base_url for Snipe-IT and GLPI
```

Set secrets as environment variables (recommended):
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export SNIPEIT_TOKEN="your-snipeit-api-token"
export GLPI_APP_TOKEN="your-glpi-app-token"
export GLPI_USER_TOKEN="your-glpi-user-token"
```

### 3. Dry run (no CMDB writes)

```bash
python3 agent/agent.py --dry-run
```

### 4. Full run

```bash
python3 agent/agent.py --config config.local.yaml
```

---

## Authentication

Credentials are resolved in this order (first wins):

| Credential        | Environment Variable  | config.yaml key            |
|-------------------|-----------------------|----------------------------|
| Anthropic API key | `ANTHROPIC_API_KEY`   | `anthropic.api_key`        |
| Snipe-IT token    | `SNIPEIT_TOKEN`       | `snipeit.api_token`        |
| GLPI app token    | `GLPI_APP_TOKEN`      | `glpi.app_token`           |
| GLPI user token   | `GLPI_USER_TOKEN`     | `glpi.user_token`          |

**Never commit secrets to the config.yaml** — always use env vars or a vault.

---

## Deployment

### Ansible (recommended for existing fleet)

```yaml
# site.yml
- hosts: all
  roles:
    - role: cmdb-agent
      vars:
        cmdb_agent_snipeit_url: "https://snipeit.your-agency.gov"
        cmdb_agent_glpi_url: "https://glpi.your-agency.gov"
        cmdb_agent_anthropic_api_key: "{{ vault_anthropic_key }}"
        cmdb_agent_snipeit_token: "{{ vault_snipeit_token }}"
        cmdb_agent_glpi_app_token: "{{ vault_glpi_app_token }}"
        cmdb_agent_glpi_user_token: "{{ vault_glpi_user_token }}"
```

The Ansible role:
- Syncs the agent code to `/opt/cmdb-agent`
- Writes `config.yaml` from the Jinja2 template (no secrets in file)
- Installs a cron job (Linux/macOS) or Scheduled Task (Windows) running every 6 hours
- Triggers an immediate first-run at provision time

### CloudFormation / AWS EC2

The `deploy/cloudformation/ec2-bootstrap.yaml` file contains:
- A `UserData` block that clones the agent from GitLab, runs it at first boot,
  and installs a cron job for periodic check-ins
- An IAM role granting only `secretsmanager:GetSecretValue` on `/vulnops/*` paths
- Secrets pulled from AWS Secrets Manager — nothing in plaintext

---

## What Claude Does

Each batch of software packages is sent to `claude-sonnet-4` with a structured
prompt. Claude returns a JSON array with:

| Field                  | Description                                               |
|------------------------|-----------------------------------------------------------|
| `cpe23`                | CPE 2.3 URI (`cpe:2.3:a:vendor:product:version:...`)      |
| `eol`                  | `true` / `false` / `null` (uncertain)                     |
| `eol_date`             | Date vendor support ended, if known                       |
| `eol_notes`            | Brief reason (e.g., "Python 3.8 EOL October 2024")        |
| `known_dependencies`   | Libraries bundled *inside* this package                   |
| `confidence`           | 0.0–1.0 confidence in CPE and EOL data                    |

The `known_dependencies` field is what makes this more valuable than a plain
scanner — it surfaces things like `log4j 1.2` bundled inside a proprietary JAR
that reports itself as "AgencyFinanceApp 4.2".

---

## Snipe-IT Custom Fields

The agent writes to these custom fields on hardware assets.
Create them in Snipe-IT under **Settings > Custom Fields**:

| Field name             | Type   | Notes                            |
|------------------------|--------|----------------------------------|
| `_snipeit_fqdn`        | text   | Fully qualified domain name      |
| `_snipeit_os`          | text   | OS name + version                |
| `_snipeit_cpu`         | text   | CPU model string                 |
| `_snipeit_ram_gb`      | text   | RAM in GB                        |
| `_snipeit_is_virtual`  | text   | "True" or "False"                |
| `_snipeit_virt_platform` | text | VMware / KVM / Docker / etc.   |

---

## Roadmap (future releases)

- [ ] CPE cross-reference against NVD to surface active CVEs per host
- [ ] Snipe-IT ↔ Tenable asset ID mapping (bridge to VulnOps vuln platform)
- [ ] SBOM (CycloneDX) export per host
- [ ] Delta-only sync (only push changed packages, not full inventory each run)
- [ ] Slack / email alert when new EOL software detected
