---
id: editions
title: CatWAF Lite and CatWAF Full
keywords: [edition, lite, full, minimal, standard, upgrade, downgrade, dashboard, headless, cli only, no ui]
questions:
  - What is the difference between CatWAF Lite and CatWAF Full?
  - Which edition am I running?
  - How do I upgrade from Lite to Full?
  - Can I run CatWAF without the dashboard?
  - Does Lite protect my site as well as Full?
related: [about-versions, getting-started, dashboard, catai-assistant]
actions: []
---

CatWAF installs in one of two editions. The choice is made at install time, stored in `.env` as `CATWAF_EDITION`, and enforced when commands run — it is a real property of the installation, not a label.

**The core WAF is identical in both:** Caddy, Coraza, OWASP CRS, paranoia levels and static rules. Runtime integrations such as challenges, CrowdSec, temporary ban enforcement and discovery controllers require the Node backend, supplied by Full. Both belong to CatWAF Free.

## CatWAF Lite

Installs Caddy with the Coraza module, the OWASP CRS, the complete `catwaf` command-line tool, and the SQLite database that stores blocked requests and events.

It deliberately installs **nothing else** — no React, no Vite, no `frontend/node_modules`, no HTTP API server, no web dashboard, no CatAI, no Docker tooling. `catwaf start` brings up the WAF; it does not start a web server, because Lite does not have one.

Everything you would do in the dashboard, you do from the terminal: `catwaf audit` for a traffic and attack summary, `catwaf explain` for why a request was blocked, `catwaf rules` to browse and toggle CRS rules, `catwaf paranoia` and `catwaf mode` to tune, `catwaf config` for snapshots and restores. Every one of these works exactly the same in both editions.

Lite suits a server you administer over SSH, a machine where you would rather not expose a web control panel at all, or an install where disk and memory matter.

## CatWAF Full

Everything in Lite, plus the HTTP API server, the built web dashboard, the Attack Map, the Threats/Logs/Rules pages, the CatAI assistant where configured, and the `catwaf docker` stack commands.

CatAI is optional even here — Full works without Ollama installed, and setup says so rather than treating it as a failure.

## Which am I running?

```
catwaf edition     # prints: lite  or  full
catwaf status      # version, edition, and per-component health
```

If you are reading this inside the dashboard, you are on Full — Lite has no web interface to read it in.

## Switching

```
catwaf setup --full     # Lite → Full
catwaf setup --lite     # Full → Lite
```

Going to Full installs the frontend dependencies, builds the dashboard and enables the API service. Going to Lite removes the API service rather than leaving it to fail on every boot.

Either direction is safe to re-run, and both preserve your WAF configuration, the event database, your rules, domain settings and admin accounts. Before switching to Lite, disable features that depend on the Node backend; otherwise the configured enforcement hop will refuse requests when the backend stops.

## Full-only commands on Lite

`catwaf docker` is the only command that requires Full. Run it on a Lite install and it tells you what is missing and how to fix it, then exits with status 5. It does not print an error trace, and it does not quietly do nothing.

## Older flag names

`catwaf setup --minimal` and `--standard` were the pre-1.0.1 spellings. They still work and map to `--lite` and `--full` exactly; using them prints a one-line note.
