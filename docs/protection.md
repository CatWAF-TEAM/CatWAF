# Protection layer

CatWAF's rule engine answers one question — *is this request malicious?* This
layer answers a different one: *should this client be talking to us at all?*

The two are deliberately separate. Coraza inspects a request's contents; the
protection layer decides about the client before the contents matter. An
address on a blocklist never reaches the CRS at all, which is both cheaper and
harder to evade.

Everything here is **off by default**. A fresh install renders exactly the
Caddyfile it rendered before this layer existed.

- [How a request is judged](#how-a-request-is-judged)
- [Active bans](#active-bans)
- [Behavioural banning](#behavioural-banning)
- [The challenge gate](#the-challenge-gate)
- [Threat intelligence](#threat-intelligence)
- [Why a feature might not be doing anything](#why-a-feature-might-not-be-doing-anything)

---

## How a request is judged

When any runtime feature is switched on, CatWAF renders a `forward_auth` hop
into the site block. Caddy asks CatWAF about the client, and CatWAF answers
allow, challenge or block.

The order matters, and it is not arbitrary:

1. **The IP allowlist.** A human's explicit allow beats every automatic
   signal. Nothing below can override it.
2. **An existing ban.** A local database lookup, so it comes before anything
   that costs a round trip.
3. **Everything else, in parallel, under one deadline.** ASN, reverse DNS,
   DNSBL, the local threat feed and the shared threat network are queried
   together. A source that times out is recorded as *unavailable* and does not
   count as either a hit or a miss.
4. **Scoring and the verdict**, recomputed for each request. Individual
   intelligence sources cache their own results; request-dependent decisions
   are not shared between URLs or visitors' credentials.

Two properties are worth knowing because they shape everything else:

**The hop fails open.** Every error path answers *allow*. `forward_auth` reads
a non-2xx as "deny", so a bug or a hiccup in this layer would otherwise take
the protected site down. A protection layer that can black-hole your site when
it breaks is worse than one that occasionally lets a bad request through.

**Signal latency is bounded.** The gather step has a 2.5-second deadline.
Anything that has not answered by then is ignored for that request. A slow
source can still add up to that deadline to the request's latency.

**Failing open has a limit you should know about.** "Fails open" covers every
error CatWAF can *answer* — a lookup that throws, a source that times out, a
malformed verdict. It cannot cover CatWAF not answering at all. If the CatWAF
API process is stopped or unreachable while the hop is rendered, Caddy's dial
fails, `forward_auth` reads that as a denial, and the protected site returns
502 on connection failure, or 504 on a response timeout. The transport allows
one second to connect and five seconds to receive response headers; reads have
a six-second deadline and writes a five-second deadline. The header deadline
fires before the read deadline to avoid an automatic retry on a stale pooled
connection doubling the wait.
A stalled API therefore fails within a bounded wait instead of leaving
connections open indefinitely. These failures do not bypass enabled challenges
or bans. The bounds apply to the enforcement hop, not the origin's own response.

This is why **every runtime feature ships disabled**, including
`tools_fingerprint`, which used to be on by default. A default install renders
no hop at all: Caddy talks straight to your application, and stopping the
CatWAF API takes away the dashboard and nothing else. Your protected sites keep
serving and keep blocking.

Turning any of them on is a deliberate trade — better detection, in exchange
for the protected site depending on the CatWAF process:

```
catwaf settings tools_fingerprint enabled=true
```

Before enabling one, it is worth knowing what you already have without it.
A default install refuses known scanner user-agents **twice**, both inside
Caddy with no network hop:

* CatWAF's own rule `9050` — sqlmap, nikto, nmap, masscan, zgrab, dirbuster,
  gobuster, wfuzz, hydra, burpsuite;
* the OWASP CRS `913` *Scanner Detection* group.

What `tools_fingerprint` adds on top is similarity scoring for user-agents that
are merely *close to* a known tool, and automatic banning of the address.
Real, but not the baseline.

Coraza and the OWASP CRS run either way. They are inside Caddy and never make a
network call, so nothing in this section affects them.

If you do enable a runtime feature on an internet-facing site, run CatWAF under
a supervisor that restarts it — `catwaf provision` installs a systemd unit that
does exactly that.

### Testing a verdict without waiting for a visitor

```
catwaf settings challenge          # see what is on
```

In the dashboard, **Protection → Threat Intel** has a "whole pipeline" lookup:
give it an address and it runs the real classification and shows every signal
that contributed, including the ones that were unavailable and why.

Via the API:

```
POST /api/protect/test    { "ip": "203.0.113.7", "uri": "/", "user_agent": "..." }
```

---

## Active bans

Before this layer, the IP blocklist was the only answer and it was entirely
manual. Now several independent features can decide to stop an address:
behavioural banning, DNSBL hits, community lists, the local threat feed, the
shared network, a failed challenge, relay detection, ASN and rDNS rules.

They all write to one store, so *"why is this visitor blocked, and how do I let
them back in"* has a single answer:

```
catwaf bans                          # everything currently refused, and by what
catwaf bans lift 203.0.113.7         # let them back in
catwaf bans list --source dnsbl      # just one source
```

Or **Protection → Active Bans** in the dashboard, grouped by source with a
"lift now" button per entry.

### Bans are temporary; your blocklist is not

| | Active bans | IP blocklist |
|---|---|---|
| Written by | any protection feature | you |
| Lifetime | expires, unless made permanent | permanent |
| Stored in | SQLite, with an expiry | the generated Coraza config |
| Cleared by | `catwaf bans clear` | never, except by you |

`catwaf bans clear` lifts every automatic ban and leaves the blocklist
untouched. That is the intended "something has gone wrong, let everyone back
in" button.

### Escalation

A repeat offender is banned for longer each time — the duration doubles per
prior ban for that address, capped by `bad_behavior.max_ban_seconds`. The
history survives the ban being lifted, which is the point: an address that has
been banned five times should not get the same 60 seconds as a first offence.

### Ranges

A ban may be a single address or a CIDR range. Ranges are matched by scanning,
so they are held separately from exact matches and only walked when any exist.
CatWAF refuses a range covering the address you are connected from — banning it
would lock you out of the dashboard along with the attacker.

---

## Behavioural banning

A scanner and a broken link look identical for one request. Over a window they
do not: a scanner generates a burst of 404s and 403s that no real client
produces.

```
catwaf settings bad_behavior enabled=true threshold=25 window_sec=60
```

**Check who it would catch before switching it on.** The dashboard's
**Behavioural Banning** page shows a dry run against your real request log, and
so does the API:

```
GET /api/protect/behavior
```

This matters more than it sounds. A legitimate client that 404s a lot — a
monitoring probe, an app with a broken asset reference, a feed reader hitting a
moved URL — is indistinguishable from a scanner by this measure. Look at the
list first.

Addresses on the IP allowlist are never banned by this, and neither is an
address that is already banned.

---

## The challenge gate

Make an unrecognised visitor prove they are a browser before the origin ever
sees them. Four tiers, cheapest first:

| Mode | What the visitor does | Stops |
|---|---|---|
| `cookie` | nothing visible; a redirect sets and checks a cookie | clients with no cookie jar |
| `javascript` | solves a small proof of work in the background | clients that do not run JS |
| `captcha` | reads CatWAF's own generated SVG image | most automation |
| `provider` | reCAPTCHA, hCaptcha, Turnstile or mCaptcha | as that service does |

```
catwaf settings challenge mode=javascript trigger=suspicious
```

### Scoping

A gate applied to everything is a gate applied to your users. `trigger`
controls when it fires, and the exemption fields carve out what must never see
it — health checks, webhook endpoints, your monitoring, known-good crawlers by
forward-confirmed reverse DNS.

The dashboard's **Challenge Gate** page has a scope tester: describe a
hypothetical request and it tells you whether that visitor would be challenged
and why. Use it on your own monitoring before turning the gate on.

(The enforcement pipeline's own test endpoint, `POST /api/protect/test`, is
admin-only and dry-run by design: it reports what *would* happen to an
address — including bans it would earn — without writing any ban or probing
the host.)

### Tokens

A solved challenge issues a signed token, bound to the address and — while the
gate is on — the browser's user agent. It cannot be handed to another client,
extended by editing it, or replayed after it expires. The cookie is `HttpOnly`,
`SameSite=Lax`, and `Secure` whenever the site is served over HTTPS.

### Canary auto-ban

Some paths are intent, not traffic — `/.env`, `/.git/config`, `/.htpasswd`.
No legitimate visitor ever requests them, so CatWAF treats the first hit as
a confession: the address is banned immediately (with repeat-offender
escalation) before any payload is evaluated. Enable under Settings → Canary
auto-ban; the path list is yours to edit. The dashboard's protection test
reports what a canary hit would do without actually banning anyone.

### Edge ban enforcement

A ban normally costs the banned client nothing but a refused forward_auth
hop. With edge enforcement on, the newest active bans are rendered straight
into the Caddyfile as a `remote_ip` matcher with an `abort` handler — the
connection dies at Caddy, no hop, no evaluation, no bytes to your origin.
The list refreshes every few seconds and within ~2 seconds of any new ban;
allowlisted addresses (in either direction of CIDR containment) are never
edge-dropped.

### Kernel-level drops (opt-in)

For hosts where you want banned addresses dead at SYN: CatWAF can mirror
active bans into an nftables set it owns (`catwaf_edge`). Requires
`CATWAF_KERNEL_BANS=1`, root, nftables, and one forwarding rule you apply
yourself:

    catwaf kernel-bans print-rules | sudo nft -f -

CatWAF touches only its own table and replaces it atomically each refresh.

### Under-attack mode

Settings → Anti-DDoS → UNDER-ATTACK MODE is the single switch for the bad
hours: every visitor gets the JavaScript challenge regardless of trigger.
Final verdicts are recomputed for each request. Slowloris-resistant connection timeouts live under
Connections (read/write/idle) and are enforced by Caddy before any route
runs.

### Previewing

The dashboard renders the real challenge page, issued by the real issuer with a
real token, rather than a mockup — so what you approve is what visitors get.

---

## Threat intelligence

Reputation signals, each independently switchable. All are off by default; none
is required by any other.

| Source | What it answers | Cost |
|---|---|---|
| **ASN** | which network owns this address | one cached DNS lookup, or none with an offline map |
| **Reverse DNS** | does the name it claims resolve back to it | one cached, forward-confirmed lookup |
| **Greylist** | should a first-time visitor wait a moment | none |
| **Community lists** | is it on a published blocklist | none per request; refreshed on a schedule |
| **DNSBL** | is it on a DNS blackhole list | one cached DNS lookup |
| **Threat feed** | has a local daemon (CrowdSec-style) flagged it | one local call |
| **Shared network** | have other CatWAF installs reported it | none per request |
| **Client probe** | is it an open proxy or relay | **a connection back to the visitor** |

### ASN without leaking your traffic

By default ASN is resolved over DNS via Team Cymru and cached. That needs
outbound DNS and tells a third party which addresses you are looking up. Set
`CATWAF_ASN_MAP` to a file of `CIDR ASN Name` lines to resolve entirely
offline.

### Reverse DNS is forward-confirmed

A reverse lookup alone is claimed by whoever controls the address's PTR record,
so it proves nothing. CatWAF resolves the name back to an address and requires
it to match. That is what makes "allow Googlebot by rDNS" safe rather than an
invitation to spoof.

### Client probing has a real cost

This one is off by default for reasons you should read before enabling it,
which is why the dashboard prints them verbatim next to the toggle:

- CatWAF opens a TCP connection back to the visitor's address. **Some networks
  and hosting providers treat that as port scanning and will file an abuse
  report against your server.**
- The first request from an unseen address waits for the probe — up to roughly
  400 ms with the defaults. Later requests are answered from cache.
- A positive result is a strong hint, not proof. Carrier-grade NAT and some
  corporate gateways legitimately have these ports open.

### Community lists

Subscribed lists are stored in their own table rather than compiled into the
Caddyfile, so a 200,000-entry list does not become a 200,000-line config.
Feeds are fetched through the same SSRF guard as every other outbound request,
parsed permissively (comments, trailing notes, CIDR notation) and strictly
(anything unparseable is counted and reported, not silently dropped).

```
catwaf cache refresh community-lists
catwaf jobs run lists.refresh
```

---

## Upload malware scanning

Off by default, and the only feature that puts CatWAF in the data path.

Everything else on this page decides from headers, so it can run as a
`forward_auth` hop: Caddy asks CatWAF for a verdict and then proxies to your
origin itself. Malware scanning needs the request *body*, which that hop never
carries. So for the upload paths you nominate — and only those — Caddy proxies
to CatWAF instead, and CatWAF forwards the request on to the same upstream once
the body has been scanned. Every other request still goes straight to your
origin, unchanged.

That means the cost is confined to uploads, and so is the blast radius: if the
feature is off, nothing is rendered into the Caddyfile at all.

```
catwaf settings upload_scan
```

**It needs a local clamd.** CatWAF never bundles an AV engine or a signature
database, and never installs one behind your back. Without clamd the feature
reports itself unavailable and traffic is unaffected:

```
GET /api/upload-scan/status
```

The installer can set it up for you, but only if asked:

```
sudo bash setup.sh --with-clamav
```

On an existing install, `apt install clamav clamav-daemon` (Debian/Ubuntu) or
`dnf install clamav clamd clamav-update` (Fedora/RHEL), then run `freshclam`
once — clamd will not start without a signature database.

**Two decisions worth making deliberately:**

`fail_open` (default on) is what happens when the scanner cannot be reached. On,
an unscannable upload reaches your origin; off, it is refused with a 503. The
default assumes a stopped clamd should not take your uploads down with it —
invert it if an unscanned upload is the worse outcome for you.

`max_scan_bytes` (default 25 MiB) is both the scan limit and the memory limit: a
verdict has to be reached before any of the body is forwarded, so that much is
buffered and no more. Anything larger is streamed past unscanned or refused,
per `oversize_action`.

To confirm the wiring end to end, send the EICAR test string through:

```
POST /api/upload-scan/test   {"content": "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"}
```

A correctly wired scanner answers with `Eicar-Test-Signature`, not `clean`.

**Do not test this by uploading `eicar.com` through a form.** It will come back
clean, and the feature is not broken. CatWAF hands clamd the request body as it
arrives on the wire, so a `multipart/form-data` upload reaches the scanner
wrapped in its MIME envelope — and ClamAV's EICAR signature is defined to match
only a file that *is* EICAR, from its first byte. `clamdscan` reports the same
"OK" for any file with bytes in front of the string; it is a property of that
test signature, not of the scan path. Real signatures are not written that way,
and ClamAV unpacks the archive and document formats malware actually arrives in.

To exercise the block path end to end rather than the scanner alone, POST the
EICAR string as the entire request body:

```
POST /upload  Content-Type: application/octet-stream
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

→ `403` with `X-CatWAF-Verdict: upload-malware`, and a `Malware found in an
upload` line in the CatWAF log. Note that CatWAF's own WAF rules run first: the
default content-type allowlist and method allowlist (`catwaf settings access`,
`catwaf settings upload_scan`) may refuse the request before the scanner ever
sees it, which is Coraza doing its job and shows up as a bodyless `403` with no
verdict header.

---

## Why a feature might not be doing anything

Three honest possibilities, in the order worth checking:

**1. The setting is on but the Caddy build cannot do it.** Response caching,
HTML injection, per-IP connection limits and DNS-01 all need optional modules.
CatWAF skips the directive rather than emitting one Caddy would reject — which
would take the whole site down — and records why:

```
catwaf doctor
```

reports what the installed Caddy supports and lists anything enabled but not in
effect. The dashboard shows the same list under "Not currently in effect" on
every configuration page.

**2. CatWAF is reading the wrong client address.** Behind Cloudflare, a load
balancer or another reverse proxy, every IP-based feature is only as accurate
as `real_ip`. If it is unset, the address CatWAF sees is the proxy's — so
everything is either allowed or banned as one client.

```
catwaf settings real_ip
```

**3. The feature is scoped away from the traffic in question.** Check the
exemptions and the trigger, then use the scope tester or `POST /api/protect/test`
against a real address.

---

## See also

- [Settings reference](settings.md) — every field in every group
- [CLI reference](cli.md#configure) — `settings`, `bans`, `jobs`, `cache`
- [Plugins](plugins.md) — the data-only extension contract
- [Metrics](metrics.md) — what to graph
