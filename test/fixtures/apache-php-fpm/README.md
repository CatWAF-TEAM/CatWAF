# Apache + PHP-FPM live fixture

The Apache counterpart of `../nginx-php-fpm`. Same split architecture, but
fronted by **Apache httpd** instead of nginx — so Apache support is proven on
its own stack rather than by relabelling the nginx one.

| Container | Image | Ports |
|---|---|---|
| `booknook_apache` | `booknook-apache` (built here, from `httpd:2.4-alpine`) | `80`, **not published** |
| `booknook_php` | `booknook-php` (built here, from `php:8.3-fpm-alpine`) | `9000`, not published |
| `booknook_db` | `catwaf-fixture-database` (patched Alpine MariaDB) | `3306`, not published |

**Nothing is published to the host.** CatWAF must discover Apache on the
Docker network and reach it without any host port mapping — and because
nothing else can reach it, CatWAF becomes the only way in.

## Run

```bash
docker compose -p booknook -f test/fixtures/apache-php-fpm/docker-compose.yml up -d --build
catwaf auto
./test/fixtures/verify-live.sh booknook apache booknook_apache   # independent proof
```

To confirm PHP really executes behind Apache (no host port, so go through the
network):

```bash
docker run --rm --network booknook_booknook curlimages/curl -s http://booknook_apache/ | head
```

## Expected output

```text
[✓] Environment detected
[✓] Web application detected  apache
[✓] WAF configured  Coraza + OWASP CRS
[✓] Protection verified

Your website is protected.

  apache  →  http://localhost:8080
```

With `--verbose`:

```text
✓ apache
  Web server: Apache  (confidence 100%)
  Runtime: PHP 8.3
  PHP-FPM backend: booknook_php:9000
  Port: 80  (Docker-internal)
  Network: booknook_booknook
```

## What this exercises

- **Apache recognition** from both the running `httpd` process and the image,
  combined into a confidence score rather than trusting one string.
- **Apache → PHP-FPM correlation** across containers: the vhost's
  `ProxyPassMatch ^/(.*\.php...)$ fcgi://booknook_php:9000/...` is read out of
  the running container and resolved to the PHP-FPM container on the shared
  network (`basis: 'config'`).
- **No convenient image tag**: the images are named `booknook-apache` and
  `booknook-php`, so neither `apache` nor `php-fpm` can be matched from the
  image alone — the running process and the config have to carry it.
- **Apache config discovery**: `Listen`, `DocumentRoot` and `VirtualHost` are
  parsed from the container's own configuration.
- **PHP-FPM is not routable**: it speaks FastCGI, so it is recognized as part
  of the application but never proxied.
- **Non-web containers**: MariaDB is correctly left alone.

## The PHP app is intentionally vulnerable

`www/index.php` reflects query input **without escaping**, following the same
convention as `docker/TestApp.Dockerfile`. That is the point: if an XSS
payload ever renders, the WAF failed. The container publishes no ports and is
reachable only through CatWAF. Do not deploy it anywhere reachable.

## SELinux

The bind mounts use `:z`. On Fedora/RHEL (SELinux enforcing) a bind mount
without a relabel gives the container `Permission denied` on the webroot.

## Tear down

```bash
docker compose -p booknook -f test/fixtures/apache-php-fpm/docker-compose.yml down -v
```

The fixture Dockerfiles apply distribution security updates and run without root.
The shared Database.Dockerfile creates only Unix-socket administrative accounts;
there is no embedded root password or remote database user. The sample pages do
not use the database: its purpose is to prove discovery rejects non-HTTP services.
Run `bash scripts/check-discovery-fixtures.sh` from the repository to build and
check both stacks; it refuses existing fixture containers and cleans up its own.
