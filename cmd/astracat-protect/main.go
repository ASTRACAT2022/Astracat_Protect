package main

import (
	"flag"
	"fmt"
	"log"

	"astracat-protect/internal/config"
	"astracat-protect/internal/server"
)

func main() {
	var (
		configPath  string
		httpListen  string
		httpsListen string
		adminListen string
	)

	flag.StringVar(&configPath, "config", "configs/astracat.Caddyfile", "Path to Caddyfile-like config")
	flag.StringVar(&httpListen, "http", ":80", "HTTP listen address (ACME + redirect)")
	flag.StringVar(&httpsListen, "https", ":443", "HTTPS listen address")
	flag.StringVar(&adminListen, "admin", ":9090", "Admin listen address")
	flag.Parse()

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if err := server.Run(cfg, server.Options{
		ConfigPath:  configPath,
		HTTPListen:  httpListen,
		HTTPSListen: httpsListen,
		AdminListen: adminListen,
	}); err != nil {
		fmt.Printf("server error: %v\n", err)
		return
	}
}
