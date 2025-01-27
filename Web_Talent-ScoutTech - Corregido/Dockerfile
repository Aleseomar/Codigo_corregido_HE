# Usa la imagen oficial de PHP con Apache y soporte para SQLite
FROM php:8.2-apache

# Actualiza los repositorios e instala SQLite3 y las extensiones necesarias
RUN apt-get update && apt-get install -y \
    sqlite3 \
    libsqlite3-dev \
    && docker-php-ext-install pdo_sqlite

# Habilita el módulo de reescritura en Apache (opcional, útil para muchas aplicaciones PHP)
# RUN a2enmod rewrite

# Configura el directorio de trabajo
WORKDIR /var/www/html

# Copia el código de tu aplicación al contenedor
COPY . /var/www/html/

# Asigna permisos correctos a los archivos
RUN chown -R www-data:www-data /var/www/html

# Expone el puerto 80 para el tráfico HTTP
EXPOSE 80

# Inicia el servidor Apache en primer plano
CMD ["apache2-foreground"]
