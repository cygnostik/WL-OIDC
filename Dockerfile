FROM php:8.4-apache AS php
RUN docker-php-ext-install pdo_mysql

FROM php AS dependencies
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer
RUN apt-get update \
 && apt-get install -y --no-install-recommends unzip \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --no-scripts

FROM php AS runtime
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
 && printf 'session.gc_maxlifetime = 28800\n' > "$PHP_INI_DIR/conf.d/pd-oidc.ini" \
 && sed -i 's/^Listen 80$/Listen 0.0.0.0:3000/' /etc/apache2/ports.conf
WORKDIR /var/www/html
COPY deploy/apache.conf /etc/apache2/sites-available/000-default.conf
COPY --from=dependencies /app/vendor/ ./vendor/
COPY public/ ./public/
COPY src/ ./src/
COPY views/ ./views/
COPY bin/ ./bin/
COPY database/ ./database/
COPY distribution/ ./distribution/
EXPOSE 3000
