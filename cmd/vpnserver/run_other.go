//go:build !linux

package main

import (
	"context"
	"log/slog"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/netsetup"
)

func run(ctx context.Context, cfg *config.Server, log *slog.Logger) error {
	return netsetup.ErrUnsupported
}
