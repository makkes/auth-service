FROM golang:1.10.3-alpine as builder

WORKDIR /go/src/github.com/makkes/services.makk.es/auth/
RUN apk add --no-cache git
COPY . .
WORKDIR cmd
RUN go get -v
ARG VERSION
RUN CGO_ENABLED=0 go build -a -o auth -ldflags "-X 'github.com/makkes/services.makk.es/auth/server.version=${VERSION}'" 

FROM scratch

COPY --from=builder /go/src/github.com/makkes/services.makk.es/auth/cmd/auth /
COPY ca-certificates.crt /etc/ssl/certs/

CMD ["/auth"]
