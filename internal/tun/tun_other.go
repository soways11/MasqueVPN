//go:build !linux && !windows

package tun

import (
	"errors"
	"runtime"
)

// ErrUnsupported — на этой платформе TUN пока не реализован.
var ErrUnsupported = errors.New("tun: платформа " + runtime.GOOS + " пока не поддерживается")

// Open на платформах без реализации всегда возвращает ErrUnsupported.
func Open(name string, mtu int) (Device, error) { return nil, ErrUnsupported }

// FromFD на платформах без реализации всегда возвращает ErrUnsupported.
func FromFD(fd int, name string, mtu int) (Device, error) { return nil, ErrUnsupported }
