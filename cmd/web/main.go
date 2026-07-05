package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Kqzz/MCsniperGO/web"
)

func main() {
	var port string
	var password string
	var bind string
	var domain string
	var certDir string
	flag.StringVar(&port, "port", "8080", "port to listen on")
	flag.StringVar(&password, "password", "", "password for web login (required)")
	flag.StringVar(&bind, "bind", "0.0.0.0", "bind address")
	flag.StringVar(&domain, "domain", "", "domain for automatic HTTPS via Let's Encrypt (recommended)")
	flag.StringVar(&certDir, "cert-dir", "./certs", "directory to store TLS certificates")
	flag.Parse()

	if password == "" {
		fmt.Fprintln(os.Stderr, "error: --password is required")
		flag.Usage()
		os.Exit(1)
	}

	port = web.ParsePort(port)
	addr := bind + ":" + port

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nshutting down...")
		os.Exit(0)
	}()

	srv, err := web.NewServer(password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := srv.ListenAndServeTLS(addr, domain, certDir); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
