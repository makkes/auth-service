FROM golang:1.10.3-alpine as builder

WORKDIR /go/src/github.com/makkes/services.makk.es/auth/
RUN apk add --no-cache git
COPY . .
WORKDIR cmd
RUN go get -v
ARG VERSION
RUN go build -o auth -ldflags "-X 'github.com/makkes/services.makk.es/auth/server.version=${VERSION}'" 

FROM alpine:latest

RUN apk update && apk add ca-certificates

WORKDIR /root
COPY --from=builder /go/src/github.com/makkes/services.makk.es/auth/cmd/auth .

CMD ["./auth"]
