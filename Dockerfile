FROM nginx:1.27-alpine

RUN apk add --no-cache bash gettext python3

COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY start.sh /start.sh
COPY auth_server.py /auth_server.py

RUN chmod +x /start.sh

EXPOSE 8080

CMD ["/start.sh"]
