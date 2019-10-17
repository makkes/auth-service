FROM golang:1.13.1 as builder

WORKDIR /auth
COPY . .
ARG VERSION
RUN make VERSION=$VERSION build

FROM scratch

COPY --from=builder /auth/cmd/auth /
COPY ca-certificates.crt /etc/ssl/certs/

CMD ["/auth"]
