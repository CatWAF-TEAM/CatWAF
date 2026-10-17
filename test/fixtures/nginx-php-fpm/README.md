# nginx + PHP-FPM live fixture

Reproduces the split PHP architecture `catwaf auto` must recognize: nginx and
PHP-FPM in **separate containers** on a shared Docker network, alongside a
database container that is not a web service.

| Container | Image | Ports |
|---|---|---|
| `freshmart_nginx` | `catwaf-fixture-nginx` (pinned stable nginx) | `80`, **not published** |
| `freshmart_php` | `fake-web-php` (built here, from `php:8.3-fpm-alpine`) | `9000`, not published |
| `freshmart_db` | `catwaf-fixture-database` (patched Alpine MariaDB) | `3306`, not published |

**Nothing is published to the host.** That is deliberate: this fixture
verifies that CatWAF discovers a Docker-internal HTTP service and reaches it
without any host port mapping — by network alias when CatWAF is
containerized, or by container IP when CatWAF runs natively on the host. A
container must not need a host port to be recognized and protected, and an
unpublished app is the safer deployment since CatWAF becomes the only way
in. Do not add a `ports:` mapping to make something pass.

## Run

```bash
docker compose -p fake-web -f test/fixtures/nginx-php-fpm/docker-compose.yml up -d --build
catwaf auto --dry-run                # discovery only — changes nothing
```

## Prove the WAF is actually in the request path

Discovery succeeding is **not** protection. To actually put the WAF in front
of the app and prove traffic traverses it:

```bash
catwaf start                                        # discover, protect, self-verify
./test/fixtures/verify-live.sh fake-web nginx freshmart_nginx   # independent proof
```

`catwaf start` reports a route as `protected` only after sending a benign
request and a CRS test payload to its own endpoint and confirming the first
was served and the second blocked. It exits non-zero if it cannot prove that.

The shared `test/fixtures/verify-live.sh` does not trust that report — it re-sends the traffic itself
and greps the **application's own access log** to confirm the blocked request
never arrived:

```text
== 1. benign request through CatWAF ==
  ok   benign request returns 200
  ok   response came from the PHP application
  ok   PHP actually executed (not served as source)

== 2. OWASP CRS test payload through CatWAF ==
  ok   attack payload is blocked (403)
  ok   blocked response does not contain the app body

== 3. the application never received the blocked request ==
  ok   app log shows the benign request
  ok   app log does NOT show the blocked request

== 4. normal traffic still works after the block ==
  ok   benign request still returns 200

PROTECTED: traffic traverses CatWAF, attacks are blocked before the application.
```

Requires `jq`. The payload is the standard inert OWASP CRS SQL-injection
signature used throughout this repo's tests, sent only to this local fixture.

To confirm PHP really executes behind nginx (no host port, so go through the
network):

```bash
docker run --rm --network fake-web_freshmart curlimages/curl -s http://nginx/ | head
```

## Expected output

```text
[✓] Environment detected
[✓] Web application detected  nginx
[✓] WAF configured  Coraza + OWASP CRS
[✓] Protection verified

Your website is protected.

  nginx  →  http://localhost:8080
```

Run with `--verbose` to see the discovery detail (web server, runtime,
PHP-FPM backend, network, confidence) and the chosen upstream.

The upstream depends on where CatWAF runs. Host-native CatWAF (the usual
case when you install it directly on Fedora/Debian/etc.) routes to the
nginx **container IP**, because a host process cannot resolve Docker's
embedded DNS name `nginx`. Containerized CatWAF attaches its proxy to
`fake-web_freshmart` and routes to `nginx:80` instead. Either way you do
not have to configure anything.

Only nginx is routable, so `catwaf auto` generates exactly one protected
route. The PHP-FPM container is recognized as part of the application but is
never itself proxied — it speaks FastCGI, not HTTP.

Because nothing is published, there is **no** host-bypass warning here — no
traffic can reach the app except through CatWAF.

## What this exercises

- **Docker-internal routing, both deployment shapes**: nginx is discovered
  via its exposed `:80` plus network membership, with no published port.
  Host-native CatWAF routes to the container IP; containerized CatWAF
  attaches to the network and routes to `nginx:80`. Reachability is proven
  with a TCP connection before anything is written.
- **Correlation via config**: nginx's `fastcgi_pass freshmart_php:9000` is
  read out of the running container and resolved to the PHP-FPM container on
  the shared network. This is `basis: 'config'` — the unambiguous path.
- **No convenient image tag**: the backend image is named `fake-web-php`, not
  `php-fpm`, so detection must use the running process and the nginx config.
- **Non-web containers**: MariaDB is correctly left alone.

To exercise the weaker `network-inference` fallback instead, remove the
`./nginx.conf` volume mount so the config can't be read; discovery then needs
a corroborating signal (the shared `./www` webroot provides `index.php`).

## Tear down

```bash
docker compose -p fake-web -f test/fixtures/nginx-php-fpm/docker-compose.yml down -v
```

The fixture Dockerfiles apply distribution security updates and run without root.
The shared Database.Dockerfile creates only Unix-socket administrative accounts;
there is no embedded root password or remote database user. The sample pages do
not use the database: its purpose is to prove discovery rejects non-HTTP services.
Run `bash scripts/check-discovery-fixtures.sh` from the repository to build and
check both stacks; it refuses existing fixture containers and cleans up its own.
