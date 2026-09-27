// Команда fpserver снимает транспортные параметры живого HTTP/3-сервера и
// сохраняет их профилем для vpnserver (пункт C1 плана: отпечаток серверной
// стороны).
//
//	fpserver -probe cloudflare-quic.com:443 -out server-profile.json
//
// Зачем: клиент у нас выглядит как Chrome, а сервер до сих пор отвечал
// умолчаниями quic-go. Придумывать «как у Google» нельзя — получится
// химера. Честный путь тот же, что и с браузером: снять параметры с
// настоящего сервера и подставить их своему.
//
// Что снимается: время простоя, окна приёма, лимиты потоков, размер кадра
// датаграммы, наличие stateless_reset_token и прочее, что сервер
// объявляет клиенту. Что из этого мы можем воспроизвести через публичный
// API quic-go — описано в internal/fingerprint/server.go.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/soways11/masquevpn/internal/fingerprint"
)

func main() {
	addr := flag.String("probe", "", "адрес сервера host:port")
	sni := flag.String("sni", "", "имя для SNI (по умолчанию host из -probe)")
	out := flag.String("out", "", "куда сохранить профиль (JSON)")
	insecure := flag.Bool("insecure", false, "не проверять сертификат")
	timeout := flag.Duration("timeout", 15*time.Second, "таймаут")
	flag.Parse()

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "нужен -probe host:port")
		flag.Usage()
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	full, err := fingerprint.CaptureParams(ctx, *addr, *sni, *insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fpserver:", err)
		os.Exit(1)
	}
	fmt.Printf("транспортные параметры %s:\n", *addr)
	fmt.Printf("  max_idle_timeout              %v\n", full.MaxIdleTimeout)
	fmt.Printf("  initial_max_data              %d\n", full.InitialMaxData)
	fmt.Printf("  initial_max_stream_data (bidi remote/local, uni)  %d / %d / %d\n",
		full.InitialMaxStreamDataBidiRemote, full.InitialMaxStreamDataBidiLocal, full.InitialMaxStreamDataUni)
	fmt.Printf("  initial_max_streams bidi/uni  %d / %d\n", full.MaxBidiStreams, full.MaxUniStreams)
	fmt.Printf("  max_datagram_frame_size       %d\n", full.MaxDatagramFrameSize)
	fmt.Printf("  active_connection_id_limit    %d\n", full.ActiveConnectionIDLimit)
	fmt.Printf("  max_ack_delay / exponent      %v / %d\n", full.MaxAckDelay, full.AckDelayExponent)
	fmt.Printf("  max_udp_payload_size          %d\n", full.MaxUDPPayloadSize)
	fmt.Printf("  disable_active_migration      %v\n", full.DisableActiveMigration)
	fmt.Printf("  stateless_reset_token         %v\n", full.HasStatelessResetToken)

	if *out == "" {
		fmt.Fprintln(os.Stderr, "\n(-out не задан — профиль не сохранён)")
		return
	}
	p, err := fingerprint.CaptureServer(ctx, *addr, *sni, *insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fpserver:", err)
		os.Exit(1)
	}
	if err := fingerprint.SaveServerProfile(*out, p); err != nil {
		fmt.Fprintln(os.Stderr, "fpserver:", err)
		os.Exit(1)
	}
	fmt.Printf("\nпрофиль сохранён: %s\n", *out)
	fmt.Println("подставить: server_profile_file в конфигурации vpnserver")
	fmt.Println("внимание: часть параметров (ack_delay, active_connection_id_limit,")
	fmt.Println("max_udp_payload_size, порядок расширений ServerHello) quic-go и")
	fmt.Println("crypto/tls воспроизвести не дают — см. internal/fingerprint/server.go")
}
