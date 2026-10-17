# CatAI

CatAI is an optional assistant in the Full-edition dashboard. It answers questions about CatWAF, reads selected live settings and statistics, and can apply supported changes when an admin asks for them. The CatWAF application and CatAI integration are Node.js; Ollama runs the separate model process.

It is **off by default** and entirely optional. Nothing else in CatWAF depends on it.

---

## What it is (and isn't)

By default, CatAI sends prompts to [Ollama](https://ollama.com) at `http://127.0.0.1:11434`. Prompts may contain your question, selected configuration values and sanitized recent log fields. With that default and an already downloaded model, generation can work without internet access. The initial model pull and some installation paths require network access. If you change `OLLAMA_URL`, that endpoint receives the prompts; use only a host and network path you trust.

Knowledge retrieval, direct action extraction, parameter checks and application use ordinary Node.js code. When direct extraction finds no action, the model may propose one through a limited tool call. The server maps that proposal to its fixed catalog, normalizes and validates the parameters, then enforces the direction policy before making a change. The model also writes the response text, which can be wrong.

This separation limits what a mistaken model response can change, but does not make a natural-language action request risk-free. Review the action card and use Undo when a request was interpreted incorrectly.

---

## Turning it on

### During setup (recommended)

`catwaf --setup` includes an optional CatAI step. It checks whether Ollama is installed, picks a model sized for your hardware, and offers to download it. Declining is a normal answer and changes nothing else about your install.

### By hand

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh -o ollama-install.sh
less ollama-install.sh          # inspect the downloaded script before running it
sh ollama-install.sh
```

Then add `CATAI_ENABLED=true` to the CatWAF `.env` file and restart CatWAF.

The next `npm run dev` or `npm start` checks Ollama, starts a local Ollama process if the binary is installed but the service is down, pulls a missing model and attempts a warm-up:

```
[catai] Model qwen3:1.7b isn't downloaded yet — pulling it now (this only happens once)…
[catai] Warming qwen3:1.7b…
[catai] CatAI is ready — the cat icon in the dashboard is good to go.
```

If Ollama isn't installed, CatWAF says so once and starts normally. The assistant reports itself unavailable rather than erroring.

### Configuration

| Variable | Default | What it does |
|---|---|---|
| `CATAI_ENABLED` | *(off)* | Must be exactly `true` to enable. Anything else, including unset, keeps it off. |
| `CATAI_MODEL` | `qwen3:1.7b` | Ollama model tag; choose a model that supports tool calls for action proposals. |
| `OLLAMA_URL` | `http://127.0.0.1:11434` | Ollama endpoint. A remote endpoint receives CatAI prompts; protect it and its network path. |
| `CATAI_KEEP_ALIVE` | `5m` | How long the model stays resident in memory between questions. The boot-time warm-up asks for `30m` so the model is still loaded when you first open the panel; setting this explicitly overrides both. |

---

## Choosing a model

CatAI defaults to `qwen3:1.7b`. Its requests currently set `num_ctx: 2048`; a model's advertised maximum context is not the context CatAI actually sends. The setup wizard may choose `qwen3:0.6b` for a smaller machine. You can override the tag with `CATAI_MODEL`, but action proposals depend on the selected model supporting Ollama tool calls.

Model memory use and latency vary with the Ollama build, quantization, context and available CPU/RAM. Measure on the target host before enabling CatAI on a small server. `CATAI_KEEP_ALIVE=0` unloads the model between requests at the cost of a cold start each time.

---

## What you can ask it

### Questions about CatWAF

Answered from a bundled knowledge base of task-oriented documents written for website owners, not security engineers.

```
what is paranoia level?
why are my customers getting blocked?
how do I block a country?
what does detection only mean?
```

If nothing in the knowledge base covers your question, CatAI says so rather than inventing an answer.

### Questions about *your* setup

These are answered from your real configuration and request log. The numbers are looked up by the server and handed to the model — it never computes or estimates them.

```
am I protected right now?
what's my security score?
how many attacks today?
what countries am I blocking?
```

### Things you want done

```
block traffic from China
set paranoia to 3
add a rule blocking any path containing xmlrpc.php
turn on audit logging
unblock Vietnam
```

---

## What it can actually change

Every action lives in a fixed catalog. The model cannot invent new ones, and anything not on this list is not reachable through chat no matter how you phrase it.

**Applied immediately, with a one-click Undo** — these all *strengthen* protection:

| Action | Example |
|---|---|
| Block an IP or range | *"block 203.0.113.9"* |
| Block a country | *"block all traffic from Brazil"* |
| Raise the paranoia level | *"set paranoia to 4"* |
| Turn protection on | *"turn the firewall on"* |
| Enable rate limiting | *"enable rate limiting"* |
| Lower the rate-limit ceiling | *"limit each IP to 60 requests a minute"* |
| Block a user agent | *"block the sqlmap user agent"* |
| Add a custom rule | *"block any request whose path contains /xmlrpc.php"* |
| Enable audit logging | *"turn on audit logging"* |

**Requires an explicit click** — these *weaken* protection, so CatAI offers and waits:

| Action | Why it asks |
|---|---|
| Allow an IP through | Bypasses every rule. Expires automatically. |
| Unblock an IP | That address can reach your site again. |
| Unblock a country | That country can reach your site again. |
| Unblock a user agent | Those requests get through again. |
| Lower the paranoia level | Less inspection. |
| Raise the rate-limit ceiling | Each visitor may make more requests. |
| Add CMS compatibility exclusions | Relaxes rules on WordPress/Drupal/etc. admin paths. |

**Not available at all.** Turning the engine off, switching to detection-only, disabling rate limiting, and disabling rule categories are absent from the catalog entirely — not merely gated behind a confirmation. These are exactly what a confused model, or a user being socially engineered, could be talked into with no friction to stop it. Use the real controls in the dashboard.

### Custom rules

`rule.add` is a constrained builder, not a free-text field. You pick what to inspect (URL path, query string, request body, headers, or user agent) and the text to match; CatWAF generates the actual Coraza directive:

```
SecRule REQUEST_URI "@contains /xmlrpc.php" "id:9301,phase:1,deny,log,msg:'CatAI: block URL path containing /xmlrpc.php'"
```

Letting a small model emit ModSecurity syntax directly would be an arbitrary-config-write primitive, and a single malformed directive breaks the Caddy reload for your whole site. Values containing quotes, backslashes, or newlines are rejected rather than escaped.

---

## How it's kept safe

**The model doesn't decide what happens.** Your message is parsed by a deterministic extractor first — regular expressions and a country lookup table. The model is only consulted when that finds nothing, and even then its answer is treated as an untrusted *proposal*: re-validated against the same catalog, the same parameter validators, and the same direction policy. A malformed or unrecognised suggestion is discarded silently.

**Action selection does not read retrieved text or logs.** Direct extraction and the model's tool-call pass receive the operator's typed message, not retrieved documents or request-log fields. Those fields can still influence the generated prose, so treat explanations based on untrusted traffic as untrusted. Action proposals still pass through the fixed catalog, parameter validation and direction policy.

**Log data is structurally fenced.** When a question genuinely needs recent requests, they're stripped of control and bidirectional characters, truncated, rendered as a fixed-width table of typed fields rather than raw text, and wrapped in markers that are repeated after the block.

**You can't lock yourself out.** `ip.block` refuses any address or range containing your own. (This guard also applies to the normal IP Blocklist page — it was missing there too.)

**Everything is audited twice.** Actions are recorded both by the underlying service and again as `catai.apply`, so AI-originated changes are distinguishable in the audit trail. Undo records `catai.undo`.

**It limits model work.** One model call at a time per Node.js process; a concurrent call receives a busy error. Rate limits are 10 questions/minute and 100/day, with a separate cap of 5 confirmed actions/minute. Ollama receives a `num_thread` setting of at most `cores - 1` (minimum 1); that is not a CPU reservation for the firewall. Three consecutive model failures open a 60-second circuit breaker.

**Read-only users get prose only.** Offers and actions require an admin role.

---

## Using it

The cat sits in the bottom-right corner of every page.

- **Drag it** anywhere you like — the position is remembered.
- **Press `/`** while the panel is open to jump straight to the chat box.
- The activity trail under the cat (*"Reading paranoia-levels.md"*, *"Checking your live stats…"*) reports real pipeline stages. Nothing is padded to look busy.

---

## Honest limitations

**It can be confidently wrong.** This is unavoidable at this model size. Answers cite which document they came from so you can check, and a persistent reminder sits under the chat box. Actions are safe; prose is not guaranteed correct.

**It can misparse.** *"block Turkey"* is unambiguous; *"block the country those attacks came from"* is not. When a parameter can't be extracted, CatAI asks rather than guesses. When it does misparse, the direction policy bounds the damage — only protective changes auto-apply, and Undo is one click.

**Latency varies by host.** Cold starts, model size and available CPU/RAM can change response times substantially. The current end-to-end security recheck did not exercise a full Ollama deployment matrix.

**It only knows CatWAF.** It has a bundled knowledge base and your live configuration. It is not a general-purpose assistant and will decline questions outside that scope rather than improvise.

---

## Troubleshooting

**"CatAI is unavailable"** — Check Ollama is running (`curl http://127.0.0.1:11434/api/tags`) and the model is pulled (`ollama list`). The status message in the panel names the specific problem.

**The cat doesn't appear** — `CATAI_ENABLED` must be exactly `true`. Restart the backend after changing `.env`.

**Answers are very slow** — You're likely on a model too large for the hardware. Switch to `CATAI_MODEL=qwen3:0.6b`. If the first question of the day is slow but later ones are fast, the model is being unloaded between questions; raise `CATAI_KEEP_ALIVE`.

**It says it can't do something you know it can** — Try naming the thing directly. *"block China"* extracts cleanly; *"can you do something about all this traffic from Asia"* does not.

---

## Testing

The deterministic half — the half that has to be correct regardless of how good or bad the model is — is covered by tests that need no Ollama and no network:

```bash
node --experimental-sqlite test/catai.test.js
```

This covers knowledge-base integrity, retrieval accuracy across 49 questions, the no-match threshold, action extraction, direction policy, the self-lockout guard, apply/undo round-trips, the concurrency gate, and graceful degradation when Ollama is unreachable.
