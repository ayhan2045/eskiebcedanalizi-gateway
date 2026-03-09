FROM nginx:1.27-alpine

RUN apk add --no-cache apache2-utils bash gettext

COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY start.sh /start.sh

RUN chmod +x /start.sh

EXPOSE 8080

CMD ["/start.sh"]
