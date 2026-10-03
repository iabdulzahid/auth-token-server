package main

import (
	"os"

	"github.com/rs/zerolog"
)

// Version and GitSHA are injected at build time via -ldflags.
// go build -ldflags="-X main.Version=v1.0.0 -X main.GitSHA=abc1234"
var (
	Version = "dev"
	GitSHA  = "unknown"
)

func main() {
	log := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("version", Version).
		Str("git_sha", GitSHA).
		Logger()

	log.Info().Msg("ATS starting")
}
