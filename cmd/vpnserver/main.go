// Команда vpnserver — сервер masquevpn: MASQUE-прокси (CONNECT-IP поверх HTTP/3),
// свой TUN, маршрутизация и NAT в интернет.
//
//	vpnserver -config /etc/masquevpn/server.json
//	vpnserver genkey            — сгенерировать общий ключ клиентов
//	vpnserver clients ...       — управление клиентами (свой ключ у каждого)
//	vpnserver ports ...         — UDP-порты сервера (основной и запасные)
//
// Нужны права root (или CAP_NET_ADMIN): TUN, ip_forward, nf_tables.
// Внешние утилиты (ip, iptables, nft) не используются — всё через netlink.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/logx"
	"github.com/soways11/masquevpn/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "clients" {
		os.Exit(clientsCommand(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "ports" {
		os.Exit(portsCommand(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println("vpnserver", version.Version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(key))
		return
	}
	cfgPath := flag.String("config", config.DefaultServerConfig(), "файл конфигурации")
	check := flag.Bool("check", false, "только проверить конфигурацию и выйти")
	flag.Parse()

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver:", err)
		os.Exit(2)
	}
	if *check {
		fmt.Println("конфигурация в порядке")
		return
	}
	log := logx.New(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("сервер остановлен с ошибкой", "err", err)
		os.Exit(1)
	}
	log.Info("сервер остановлен")
}
