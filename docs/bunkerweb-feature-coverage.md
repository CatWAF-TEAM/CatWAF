# BunkerWeb comparison: requested Free features

Reference inventories: [BunkerWeb features](https://docs.bunkerweb.io/latest/features/)
and [integrations](https://docs.bunkerweb.io/latest/integrations/), reviewed
2026-10-17. This is capability coverage for the requested additions, not a claim
that every BunkerWeb plugin, setting, behavior or deployment mode is equivalent.
CatWAF's application and controllers remain Node.js; the original upstream
Caddy/Coraza inspection dependency remains unchanged.

| Capability | CatWAF Free implementation | Practical boundary |
|---|---|---|
| Built-in bot challenges | Cookie round trip, JavaScript work challenge, local image CAPTCHA | Cookie/JS checks do not establish humanity; image solvers remain possible |
| Provider CAPTCHA | reCAPTCHA v2, hCaptcha, Turnstile, mCaptcha | Operator credentials required; provider contracts tested with fixtures, not live accounts |
| Cookie checks | Pending HttpOnly cookie, signed client/policy-bound pass cookie, expiry and replay guards | Backend required; policy changes invalidate existing passes |
| Manual rules | Structured custom Coraza rules, CRS toggles/exclusions, administrator raw directives | Global rules shared by managed hosts; not BunkerWeb's plugin format |
| Basic bans | IP/CIDR deny/allow lists; expiring/permanent manual bans; lift/clear | First runtime ban activates the backend gate; explicit IP allows take precedence |
| CrowdSec bouncer | Native Local API query, IP/Range bans and CAPTCHA decisions | Query mode, no streaming/metrics push; revocation bounded by cache TTL |
| Docker autoconf | Label-driven host/path/upstream routes, scoped policy, optional orphan removal | Network must be shared with proxy; no Swarm controller |
| Kubernetes ingress | Namespace/class-scoped v1 Ingress controller, Service ports, TLS Secrets, reconciliation | One replica, polling, no Gateway API/status updates; explicit unsupported cases fail closed |
| TLS and headers | Existing Caddy TLS, custom certs, mTLS settings, security headers, cookie flags, CORS | Some settings depend on installed Caddy modules |
| Reputation and behavior | Existing DNSBL, ASN/rDNS, community lists, scanner fingerprints, behavioral/canary bans | Optional data sources and explicit failure policies |
| Operations | Existing dashboard, CLI, jobs, backups, reports, metrics and CatAI help | Full installation runs Node backend; Lite does not support runtime integrations |

The BunkerWeb ecosystem also includes NGINX-specific directives/plugins,
managed threat-network services, deployment integrations and edition-specific
features. These have not all been recreated. Rate/connection limiting, response
caching and some content transforms already have CatWAF settings but may require
additional upstream modules; settings alone do not establish working parity.
The renderer reports unsupported settings. Do not enable them based solely on
this inventory.

The current strict release checks still expose reload connection resets and an
unsuppressed upstream advisory. Audit lifetime is fixed and the Kubernetes
deployment has passed the documented real-cluster checks. See
[current validation](reliability-followup-2026-10-17.md),
[setup](orchestration.md) and [protection configuration](protection.md).
