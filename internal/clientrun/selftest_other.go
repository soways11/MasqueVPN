//go:build !windows

package clientrun

import (
	"errors"
	"log/slog"
)

// selftest — самопроверка платформенной части; реализована только на Windows,
// где её нечем заменить (на Linux то же самое покрывают тесты в netns).
func Selftest(full bool, seconds int, log *slog.Logger) error {
	return errors.New("самопроверка реализована только на Windows")
}
