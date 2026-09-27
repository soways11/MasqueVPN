//go:build utls

// Команда fpcapture снимает QUIC-отпечаток с клиента (браузера) и сохраняет его
// в JSON, пригодный для utlsquic.Config.CustomSpec.
//
// Зачем: встроенные профили uquic заканчиваются на Chrome 115 (2023 год), новых
// не будет — у uquic нет версий выше v0.0.6, а из спеков uTLS QUIC-профиль не
// собрать (там нет транспортных параметров QUIC). Единственный честный источник
// свежего отпечатка — настоящий браузер.
//
// # Как пользоваться
//
//	fpcapture -addr :8443 -out chrome.json -source "Chrome 141, macOS"
//
// Утилита слушает UDP и ждёт первый вылет QUIC-клиента. Отвечать она не умеет и
// не должна: ClientHello уходит до того, как клиент увидит ответ. Клиент
// посчитает подключение неудачным — это нормально, отпечаток уже снят.
//
// Направить браузер на этот порт:
//
//	chrome --origin-to-force-quic-on=ваш.домен:8443 https://ваш.домен:8443/
//
// Браузеры разборчивы: Chrome не выполняет QUIC на loopback и требует
// доверенный сертификат для настоящего соединения. Надёжнее запускать на машине
// с обычной сетью и доменом, а не в контейнере. Подойдёт и любой другой
// QUIC-клиент — утилита снимает отпечаток с того, кто пришёл.
//
// # Обновление отпечатка
//
// Перезапуск этой команды по расписанию (например, раз в месяц в CI на машине с
// браузером) и подмена JSON — вот и всё обновление. Перекомпиляция не нужна.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/soways11/masquevpn/internal/utlsquic"
)

func main() {
	addr := flag.String("addr", ":8443", "UDP-адрес для прослушивания")
	out := flag.String("out", "fingerprint.json", "куда сохранить отпечаток")
	source := flag.String("source", "", "описание источника, например \"Chrome 141, macOS\"")
	wait := flag.Duration("wait", 60*time.Second, "сколько ждать клиента")
	packets := flag.Int("packets", 4, "сколько пакетов первого вылета собрать")
	flag.Parse()

	pc, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("не удалось занять %s: %v", *addr, err)
	}
	defer pc.Close()
	fmt.Fprintf(os.Stderr, "слушаю %s, жду QUIC-клиента (до %s)...\n", pc.LocalAddr(), *wait)

	var pkts [][]byte
	deadline := time.Now().Add(*wait)
	for len(pkts) < *packets {
		if err := pc.SetReadDeadline(deadline); err != nil {
			break
		}
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if len(pkts) == 0 {
			fmt.Fprintf(os.Stderr, "клиент %s подключается...\n", from)
		}
		pkts = append(pkts, buf[:n])
	}
	if len(pkts) == 0 {
		log.Fatal("клиент не пришёл: ни одного пакета не получено")
	}
	fmt.Fprintf(os.Stderr, "получено пакетов: %d\n", len(pkts))

	src := *source
	if src == "" {
		src = "не указан"
	}
	fp, err := utlsquic.CaptureFromPackets(pkts, src)
	if err != nil {
		log.Fatalf("снять отпечаток не удалось: %v", err)
	}

	// Сразу проверяем, что из записи собирается рабочий профиль: лучше узнать
	// об этом здесь, чем при подключении.
	if _, err := fp.Spec(); err != nil {
		log.Fatalf("отпечаток снят, но профиль из него не собирается: %v", err)
	}
	if err := utlsquic.SaveFingerprint(*out, fp); err != nil {
		log.Fatalf("сохранение: %v", err)
	}

	fmt.Fprintf(os.Stderr,
		"готово: %s\n  источник: %s\n  расширений: %d, транспортных параметров: %d\n"+
			"  датаграмма: %d байт, DCID=%d SCID=%d\n",
		*out, fp.Source, len(fp.Extensions), len(fp.TransportParams),
		fp.DatagramSize, fp.DestConnIDLen, fp.SrcConnIDLen)
}
