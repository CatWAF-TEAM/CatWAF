---
id: bot-challenges
title: Bot challenges, CAPTCHA and CrowdSec
keywords: [captcha, recaptcha, hcaptcha, turnstile, mcaptcha, cookie, bot, challenge, crowdsec, bouncer, ban]
questions:
  - How do I enable CAPTCHA or reCAPTCHA?
  - How does CatWAF check visitor cookies?
  - How do I connect a CrowdSec bouncer?
  - How do I ban or unban an IP?
related: [orchestration, editions, ip-blacklist]
actions: []
---

Protection → Challenge Gate offers cookie, JavaScript, local image CAPTCHA and provider modes. Cookie mode proves a real cookie round trip. JavaScript mode adds a work puzzle but bots can solve it. Image CAPTCHA renders pixels without exposing the answer as HTML text; automated solvers remain possible. Provider mode supports reCAPTCHA v2, hCaptcha, Turnstile and self-hosted mCaptcha. Enter keys in the dashboard, never in chat. Set expected provider hostnames if needed; provider responses must match allowed hosts and freshness checks. Changing challenge policy invalidates existing solved cookies.

Protection → Threat Intel → CrowdSec bouncer uses a read-only CrowdSec Local API key, base URL and /v1/decisions. IP and Range bans are checked with expiry. CAPTCHA decisions require image CAPTCHA or provider mode; if neither is active they block. Automatic community allows and path exemptions cannot override CrowdSec enforcement, but the administrator's explicit IP allowlist can. The default cache is 60 seconds; deletion can take that long to be observed. A bouncer outage follows fail_open; disabling it also blocks on the signal deadline. An unexpected enforcement exception returns 503 instead of bypassing configured security.

Active Bans supports permanent or expiring IP/CIDR bans and lifting them. Adding the first manual runtime ban enables the backend enforcement gate transactionally. If validation/reload fails, the ban and activation roll back. Runtime bans, challenges and CrowdSec need the Full edition's Node backend. Lite can use static IP blacklist rules. Global custom Coraza rules remain available under Rules. The absence of a live provider-account test or a real cluster conformance test must not be described as verified production compatibility.
