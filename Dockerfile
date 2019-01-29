FROM golang:1.11.5-alpine as builder

WORKDIR /auth/
RUN apk add --no-cache git
COPY . .
WORKDIR cmd
ARG VERSION
RUN CGO_ENABLED=0 go build -a -o auth -ldflags "-X 'github.com/makkes/services.makk.es/auth/server.version=${VERSION}'" 

FROM scratch

COPY --from=builder /auth/cmd/auth /
COPY ca-certificates.crt /etc/ssl/certs/

CMD ["/auth"]
