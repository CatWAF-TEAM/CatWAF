# Apache front end for the split PHP-FPM fixture.
#
# The official httpd image ships mod_proxy and mod_proxy_fcgi but leaves
# them disabled, so they are enabled here — that is what makes the
# `ProxyPassMatch ... fcgi://` line in vhost.conf actually work, and it is
# the wiring discovery/fastcgi.js correlates on.

FROM httpd:2.4-alpine@sha256:3440c39d8d6f54fa9ad2549e5a60c19ddd435faadc29c1ad28aa795f71888889
RUN apk upgrade --no-cache

RUN sed -i \
    -e 's|^#\(LoadModule proxy_module\)|\1|' \
    -e 's|^#\(LoadModule proxy_fcgi_module\)|\1|' \
    /usr/local/apache2/conf/httpd.conf

COPY vhost.conf /usr/local/apache2/conf/extra/booknook.conf
RUN echo 'Include conf/extra/booknook.conf' >> /usr/local/apache2/conf/httpd.conf

RUN chown -R www-data:www-data /usr/local/apache2/logs
USER www-data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1

EXPOSE 80
