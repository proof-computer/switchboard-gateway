FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
  && mkdir -p /etc/nginx/certs \
  && openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -subj "/CN=*.ingress.test" \
    -addext "subjectAltName=DNS:*.ingress.test,DNS:localhost" \
    -keyout /etc/nginx/certs/tls.key \
    -out /etc/nginx/certs/tls.crt

COPY docker/tls-test-upstream/default.conf /etc/nginx/conf.d/default.conf
