# Apache y ModSecurity de Debian. La versión del paquete se registra al construir
# la imagen; no es el RPM ea-apache24-mod_security2 de cPanel.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends apache2 libapache2-mod-security2 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod security2 \
    && mkdir -p /etc/modsecurity/hostium /var/log/apache2 \
    && dpkg-query -W -f 'modsecurity ${Version}\n' libapache2-mod-security2 > /etc/hostium-modsec-version.txt \
    && apache2 -v >> /etc/hostium-modsec-version.txt

COPY hostium-only.conf /etc/apache2/conf-available/hostium-waf.conf
RUN a2enconf hostium-waf

EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
