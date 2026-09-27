//go:build !linux && !windows

package clientrun

import (
	"context"
	"log/slog"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/netsetup"
)

func Run(ctx context.Context, cfg *config.Client, log *slog.Logger, hooks Hooks) error {
	return netsetup.ErrUnsupported
}
