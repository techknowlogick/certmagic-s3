FROM caddy:2.10.0-builder AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY . /build/certmagic-s3/

RUN xcaddy build \
    --with github.com/techknowlogick/certmagic-s3=/build/certmagic-s3

FROM gcr.io/distroless/static-debian12:latest

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/caddy /usr/bin/caddy

EXPOSE 80 443 2019

ENTRYPOINT ["/usr/bin/caddy"]

CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
