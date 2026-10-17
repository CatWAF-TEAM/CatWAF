# A real, disposable non-HTTP service for discovery classification only.
# The PHP sample pages do not use this database. No remote database accounts
# or embedded passwords are created; administration uses Unix socket auth.
FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
RUN apk upgrade --no-cache && apk add --no-cache mariadb mariadb-client \
    && mkdir -p /var/lib/mysql /run/mysqld \
    && chown -R mysql:mysql /var/lib/mysql /run/mysqld
USER mysql
RUN mariadb-install-db --datadir=/var/lib/mysql --auth-root-authentication-method=socket --auth-root-socket-user=mysql --skip-test-db
EXPOSE 3306
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --user=mysql --execute='SELECT 1' >/dev/null || exit 1
CMD ["mariadbd", "--datadir=/var/lib/mysql", "--socket=/run/mysqld/mysqld.sock", "--pid-file=/run/mysqld/mysqld.pid", "--bind-address=0.0.0.0", "--skip-networking=0", "--skip-name-resolve"]
