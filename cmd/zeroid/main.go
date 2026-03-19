package main

import (
	"flag"
	"os"

	zeroid "github.com/highflame-ai/zeroid"
	"github.com/rs/zerolog/log"
)

func main() {
	configFile := flag.String("config", "", "Path to configuration file")
	flag.Parse()

	// Use ZEROID_CONFIG_FILE env var as fallback if no flag provided.
	cfgPath := *configFile
	if cfgPath == "" {
		cfgPath = os.Getenv("ZEROID_CONFIG_FILE")
	}

	cfg, err := zeroid.LoadConfig(cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	srv, err := zeroid.NewServer(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize server")
	}

	if err := srv.Start(); err != nil {
		log.Fatal().Err(err).Msg("Server error")
	}
}
