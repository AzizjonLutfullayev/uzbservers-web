FROM php:8.3-apache
RUN docker-php-ext-install mysqli pdo pdo_mysql && a2enmod rewrite headers
COPY website/ /var/www/html/
RUN chown -R www-data:www-data /var/www/html
EXPOSE 80
