// Package logx — настройка журнала для бинарников.
package logx

import (
	"log/slog"
	"os"
	"strings"
)

// New создаёт текстовый журнал в stderr с уровнем level
// (debug, info, warn, error; по умолчанию info).
func New(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
