//go:build linux

// Утилита acmeca — тестовый удостоверяющий центр ACME для стенда.
//
// Нужна затем, чтобы проверить выпуск сертификата НАСТОЯЩИМ бинарником
// сервера: он сам сходит за сертификатом, сам пройдёт проверку владения
// доменом (удостоверяющий центр придёт к нему на TCP/443 с ALPN
// «acme-tls/1»), а клиент затем подключится, доверяя только корню этого
// центра. Без такого стенда «ACME работает» осталось бы словами: настоящий
// Let's Encrypt требует публичного домена и сети.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/soways11/masquevpn/internal/acme/acmetest"
)

func main() {
	listen := flag.String("listen", "203.0.113.2:8081", "адрес центра")
	target := flag.String("target", "10.0.0.1:443", "куда идти на проверку владения доменом")
	caOut := flag.String("ca-out", "", "куда сохранить корневой сертификат (PEM)")
	lifetimeDays := flag.Int("days", 90, "срок выпускаемых сертификатов")
	flag.Parse()

	ca, err := acmetest.New("http://" + *listen)
	if err != nil {
		log.Fatal(err)
	}
	ca.SetTarget(*target)
	ca.Lifetime = time.Duration(*lifetimeDays) * 24 * time.Hour
	ca.Logf = func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	if *caOut != "" {
		if err := os.WriteFile(*caOut, ca.PEM(), 0o644); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("удостоверяющий центр запущен listen=%s target=%s\n", *listen, *target)
	if err := http.ListenAndServe(*listen, ca.Handler()); err != nil {
		log.Fatal(err)
	}
}
