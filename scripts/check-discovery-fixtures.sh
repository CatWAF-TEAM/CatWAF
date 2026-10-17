#!/usr/bin/env bash
set -euo pipefail
root="${CATWAF_FIXTURE_OUTPUT:-$(mktemp -d)}"
mkdir -p "$root/logs"
cd "$(dirname "$0")/.."
# Never replace or clean up an operator's existing fixture containers.
for container in booknook_apache booknook_php booknook_db freshmart_nginx freshmart_php freshmart_db; do
  if docker container inspect "$container" >/dev/null 2>&1; then
    echo "Refusing to replace existing container: $container" >&2
    exit 1
  fi
done
trap 'docker compose -p catwaf-check-apache -f test/fixtures/apache-php-fpm/docker-compose.yml logs > "$root/logs/fixture-apache-runtime.log" 2>&1; docker compose -p catwaf-check-nginx -f test/fixtures/nginx-php-fpm/docker-compose.yml logs > "$root/logs/fixture-nginx-runtime.log" 2>&1; docker compose -p catwaf-check-apache -f test/fixtures/apache-php-fpm/docker-compose.yml down --volumes; docker compose -p catwaf-check-nginx -f test/fixtures/nginx-php-fpm/docker-compose.yml down --volumes' EXIT
for fixture in apache nginx; do
  compose="test/fixtures/$fixture-php-fpm/docker-compose.yml"
  docker compose -p "catwaf-check-$fixture" -f "$compose" up -d --build
done
for entry in 'booknook_apache BookNook' 'freshmart_nginx FreshMart'; do
  read -r container expected <<< "$entry"
  ok=0
  for attempt in $(seq 1 30); do
    if docker exec "$container" wget -q -O - http://127.0.0.1/ > "$root/logs/$container.html" && grep -qi "$expected" "$root/logs/$container.html" && ! grep -q '<?php' "$root/logs/$container.html"; then ok=1; break; fi
    sleep 1
  done
  test "$ok" = 1
  printf 'PASS %s: PHP page executed through web server\n' "$container"
done
for container in booknook_apache booknook_php freshmart_php freshmart_nginx booknook_db freshmart_db; do
  test "$(docker exec "$container" id -u)" != 0
  for attempt in $(seq 1 40); do
    status=$(docker inspect --format '{{.State.Health.Status}}' "$container")
    test "$status" = healthy && break
    sleep 1
  done
  test "$status" = healthy
  printf 'PASS %s: non-root and healthy\n' "$container"
done
for container in booknook_db freshmart_db; do
  docker exec "$container" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --user=mysql -e 'SELECT 1'
  if docker exec "$container" mariadb --protocol=tcp -h 127.0.0.1 --user=root --skip-password -e 'SELECT 1'; then echo ERROR-passwordless-root-TCP; exit 1; fi
  if docker exec "$container" mariadb --protocol=tcp -h 127.0.0.1 --user=anonymous --skip-password -e 'SELECT 1'; then echo ERROR-anonymous-TCP; exit 1; fi
  printf 'PASS %s: Unix socket administration works and passwordless TCP access is refused\n' "$container"
done
