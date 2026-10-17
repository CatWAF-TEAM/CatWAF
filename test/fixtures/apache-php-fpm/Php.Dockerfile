# PHP-FPM backend for the Apache split-architecture fixture.
#
# Built as `booknook-php` — an image name that does NOT contain "php-fpm",
# so correlation has to rely on the running process and the Apache config
# rather than a convenient image tag. That is the realistic case.

FROM php:8.3-fpm-alpine@sha256:454b11c8907e32878ce92e87b13c14e1bbe6e1b10f4f96d4a19c9b62ec675d41
RUN apk upgrade --no-cache

WORKDIR /var/www/html
COPY www/ /var/www/html/

EXPOSE 9000
USER www-data
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["php", "-r", "$s=@fsockopen('127.0.0.1',9000,$errno,$error,3);if(!$s){exit(1);}fclose($s);"]
CMD ["php-fpm", "-F"]
