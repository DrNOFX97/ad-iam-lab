# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

`ad-iam-lab` is a documentation-and-scripts portfolio project (Portuguese, European Portuguese spelling throughout) for a fictitious company, Nortada Logística, Lda. It models an Active Directory / IAM lab: OU structure, AGDLP security groups, RBAC, onboarding/offboarding, audit policy, and Wazuh SIEM integration. There is no application code, no build system, no package manager, and no test suite — the deliverables are PowerShell scripts (`scripts/`), design docs (`docs/`), reference data (`data/`), and Wazuh config (`wazuh/`).

**Nothing in this repo has been executed against a real domain controller yet.** Every script, doc, and rule file describes an intended/designed behavior, not an observed one. When editing any of these files, do not invent execution results, validation outcomes, or "confirmed working" claims — state design intent, and if something has genuinely been run and observed, say so explicitly (this distinction is treated as important throughout the existing docs and script `.NOTES` blocks).

There is no CLAUDE.md-relevant build/lint/test command: there is nothing to compile or run in CI. The only "validation" available locally is PowerShell script analysis (see below) and manual read-through against the docs.

## Repository structure

- `README.md` — canonical overview: company model, architecture diagram, execution order, directory layout, and a "Porquê cada decisão" (design rationale) section that is the most important section for understanding *why*, plus an "Estado atual do projeto" section tracking what exists vs. what's still pending.
- `docs/01` through `docs/07` — sequential design docs (architecture, DC install, OU/group structure, audit policy, onboarding/offboarding, RBAC, Wazuh integration). Scripts and data files reference these docs by number/section in comments; keep that cross-referencing intact when editing either side.
- `scripts/00` through `scripts/05` — PowerShell scripts, meant to run in order against a real `NORTADA-DC01` domain controller:
  - `00-Install-DomainController.ps1` — promotes the DC, creates the `nortada.local` forest.
  - `01-New-OuStructure.ps1` — builds the OU tree under `OU=NORTADA`.
  - `02-New-SecurityGroups.ps1` — creates AGDLP groups (`GG-*` global, `DL-*` domain local) and wires GG members into DL groups.
  - `03-Onboard-Users.ps1` — creates accounts from `data/colaboradores.csv`, assigns groups from `data/rbac_baseline.json`.
  - `04-Offboard-User.ps1` — disables/reposes/moves accounts from `data/saidas.csv`.
  - `05-Set-AuditPolicy.ps1` — sets Advanced Audit Policy subcategories and grows the Security log.
- `data/colaboradores.csv`, `data/saidas.csv` — sample HR data (28 fictitious employees) driving onboarding/offboarding.
- `data/rbac_baseline.json` — single source of truth mapping job title (`cargo`) → `departamento`, `grupos_permitidos`, `grupos_proibidos`, `nivel_risco`, and optional `conta_associada`. Both `03-Onboard-Users.ps1` and the planned SentryLens privilege-drift detection read this file; keep it in sync with `docs/06-rbac.md`.
- `wazuh/local_rules.xml`, `wazuh/ossec-agent-windows.conf` — local Wazuh Manager rules and agent config excerpt for the DC. Only Event IDs 4723/4724 get local rules (level 3); the other 17 relevant AD Event IDs already have rules in Wazuh's base ruleset — see the top-of-file comment in `local_rules.xml` before adding new rules, to avoid duplicating alerts the base ruleset already produces.
- `evidencias/` — placeholder for future screenshots/evidence from real lab execution; currently empty (`.gitkeep` only).

## Key conventions to preserve when editing

- **Language**: all prose, comments, script output, log messages, and identifiers within scripts are in European Portuguese. Match this in any new content.
- **Account naming**: normal accounts `primeiro.ultimo`; administrative accounts `adm.primeiro.ultimo` (PAM separation — never grant department groups to `adm.*` accounts, never reuse a normal account's group memberships for its admin twin).
- **AGDLP model**: `GG-*` (global groups, department/role — "who") feed into `DL-*` (domain local groups, resource — "what"). Don't grant permissions directly to users or to global groups; go through domain local groups.
- **Idempotency**: every script that touches AD state (`00`–`05`) checks for existing objects before creating/modifying them (`Get-AD*` before `New-AD*`), supports `-WhatIf` via `[CmdletBinding(SupportsShouldProcess)]`, and logs to `scripts/logs/` (gitignored). Preserve this pattern in any new or modified script — don't introduce non-idempotent AD calls.
- **Fail closed on RBAC**: if `03-Onboard-Users.ps1` encounters a `Cargo` not present in `data/rbac_baseline.json`, it must NOT assign any default/guessed groups — it logs a warning and leaves the account groupless. Preserve this when touching onboarding logic.
- **Offboarding never deletes**: `04-Offboard-User.ps1` disables, resets password, strips group membership, and moves the account to `OU=Contas-Desativadas`; it must never call `Remove-ADUser`/`Remove-ADObject`. This is deliberate (forensic retention, avoiding orphaned SIDs on file ownership) — see README "Porquê cada decisão" and `docs/05-onboarding-offboarding.md` §3.3.
- **Passwords**: generated passwords are built directly as `SecureString` via a cryptographic RNG and never persisted or logged in plaintext.
- **Wazuh rule IDs**: local custom rules use the `100000`–`119999` reserved range (currently `100723`, `100724`), chosen mnemonically from the Windows Event ID they cover.
- **Cross-references**: scripts and docs cite each other by path and section number (e.g. "ver docs/03-estrutura-ou-grupos.md, secção 3.1"). When changing behavior, update both the script's comment-based help / `.NOTES` and the referenced doc section so they stay consistent.
- **Log/evidence files are gitignored** (`scripts/logs/`, `*.log`, `*_export.csv`, `.evtx`, etc. — see `.gitignore`) — don't commit generated logs or credentials.

## Working with the PowerShell scripts

There's no test harness; the closest thing to validation is:

```powershell
# Syntax/style check a script (requires PSScriptAnalyzer if installed)
Invoke-ScriptAnalyzer -Path scripts\01-New-OuStructure.ps1

# Dry-run against a real domain (requires RSAT ActiveDirectory module and a real DC)
.\scripts\01-New-OuStructure.ps1 -WhatIf
```

All scripts require the `ActiveDirectory` RSAT module and a live `nortada.local` domain to actually run — this environment does not have one, so treat any change as unverified until the user confirms it was run against the real lab (`docs/` explicitly track "Estado atual do projeto" / what's designed vs. what's been executed — update the README's status section if a script gets run for real).
