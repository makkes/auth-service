package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	log "github.com/makkes/justlib/logging"

	"github.com/makkes/services.makk.es/auth/server"
)

func buildURL(proto, host, port string) string {
	var urlBuilder strings.Builder
	urlBuilder.WriteString(fmt.Sprintf("%s://%s", proto, host))
	if port != "" {
		urlBuilder.WriteString(fmt.Sprintf(":%s", port))
	}
	return urlBuilder.String()
}

func main() {
	listenHost := os.Getenv("LISTEN_HOST")
	if listenHost == "" {
		listenHost = "localhost"
	}
	listenPort := os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "4242"
	}
	serveProtocol := os.Getenv("SERVE_PROTOCOL")
	if serveProtocol == "" {
		serveProtocol = "https"
	}
	serveHost := os.Getenv("SERVE_HOST")
	if serveHost == "" {
		serveHost = "localhost"
	}
	servePort := os.Getenv("SERVE_PORT")
	if servePort == "80" || servePort == "443" {
		servePort = ""
	}
	baseURL := buildURL(serveProtocol, serveHost, servePort)
	s := server.NewServer(
		baseURL,
	)

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGTERM)
	go func() {
		for ch := range sigCh {
			if ch == syscall.SIGTERM {
				log.Info("Shutting down on SIGTERM...")
				s.Stop()
			}
		}
	}()

	err := s.Start(listenHost, listenPort)
	if err != nil {
		log.Fatal("%s", err)
	}
}
