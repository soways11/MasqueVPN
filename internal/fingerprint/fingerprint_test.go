package fingerprint

import (
	"crypto/tls"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestChromeProfileValues(t *testing.T) {
	q := Chrome().QUICConfig()
	if len(q.Versions) != 1 || q.Versions[0] != quic.Version1 {
		t.Fatalf("предлагается не только v1: %v", q.Versions)
	}
	if q.InitialPacketSize != 1200 {
		t.Fatalf("InitialPacketSize=%d, want 1200", q.InitialPacketSize)
	}
	if !q.DisablePathMTUDiscovery {
		t.Fatal("Path MTU Discovery должен быть выключен для стабильного размера")
	}
	if !q.EnableDatagrams {
		t.Fatal("датаграммы обязательны для CONNECT-IP")
	}
	if q.MaxConnectionReceiveWindow != 15*1024*1024 {
		t.Fatalf("окно соединения %d", q.MaxConnectionReceiveWindow)
	}
}

func TestTLSConfig(t *testing.T) {
	base := &tls.Config{ServerName: "example.com"}
	c := Chrome().TLSConfig(base)
	if base.ServerName != "example.com" || len(base.NextProtos) != 0 {
		t.Fatal("исходный TLS-конфиг изменён")
	}
	if len(c.NextProtos) != 1 || c.NextProtos[0] != "h3" {
		t.Fatalf("ALPN %v", c.NextProtos)
	}
	if c.MinVersion != tls.VersionTLS13 || c.MaxVersion != tls.VersionTLS13 {
		t.Fatal("TLS должен быть строго 1.3")
	}
	if c.ServerName != "example.com" {
		t.Fatal("ServerName должен сохраниться")
	}
}
