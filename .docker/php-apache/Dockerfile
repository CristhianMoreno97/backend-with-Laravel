FROM php:8.1-apache

# Set environment variables
ENV APP_HOME /var/www/html
ENV USERNAME=www-data
ARG HOST_UID=1000
ARG HOST_GID=1000

COPY php.ini /usr/local/etc/php/
COPY 000-default.conf /etc/apache2/sites-available/000-default.conf

RUN apt-get update \
    && apt-get install -y libzip-dev \
    && apt-get install -y zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install zip pdo_mysql
RUN a2enmod rewrite


# create document root, fix permissions for www-data user and change owner to www-data
RUN rm -r $APP_HOME
RUN mkdir -p $APP_HOME/public && \
    mkdir -p /home/$USERNAME && chown $USERNAME:$USERNAME /home/$USERNAME \
    && usermod -o -u $HOST_UID $USERNAME -d /home/$USERNAME \
    && groupmod -o -g $HOST_GID $USERNAME \
    && chown -R ${USERNAME}:${USERNAME} $APP_HOME

# Node.js, NPM, Yarn
RUN curl -sL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs
RUN npm install npm@latest -g
RUN npm install yarn -g

# Composer
RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
RUN php composer-setup.php
RUN php -r "unlink('composer-setup.php');"
RUN mv composer.phar /usr/local/bin/composer

ENV COMPOSER_ALLOW_SUPERUSER 1
ENV COMPOSER_HOME /composer
ENV PATH $PATH:/composer/vendor/bin
RUN composer config --global process-timeout 3600
RUN composer global require "laravel/installer"

# set working directory
WORKDIR $APP_HOME
USER ${USERNAME}

# copy source files and config file
# COPY --chown=${USERNAME}:${USERNAME} . $APP_HOME/
# COPY --chown=${USERNAME}:${USERNAME} .env.$ENV $APP_HOME/.env

USER root

# CMD ["apache2-foreground"]