// Package masque реализует CONNECT-IP (RFC 9484) поверх HTTP/3 (quic-go).
//
// Слои протокола:
//
//	QUIC (RFC 9000) + TLS 1.3
//	└─ HTTP/3 (RFC 9114), SETTINGS: ENABLE_CONNECT_PROTOCOL=1, H3_DATAGRAM=1
//	   └─ Extended CONNECT (RFC 9220), :protocol = "connect-ip"
//	      ├─ поток запроса: Capsule Protocol (RFC 9297)
//	      │    ADDRESS_ASSIGN (0x01), ADDRESS_REQUEST (0x02), ROUTE_ADVERTISEMENT (0x03)
//	      └─ HTTP Datagrams (RFC 9297): Quarter Stream ID | Context ID | IP-пакет
//	            Context ID = 0 — полный IP-пакет (единственный, который мы поддерживаем)
//
// Роли асимметричны (remote-access VPN):
//   - сервер выдаёт клиенту адрес (ADDRESS_ASSIGN) и объявляет маршруты
//     (ROUTE_ADVERTISEMENT), обычно весь адресный диапазон;
//   - клиент отправляет пакеты с src ∈ выданных адресов и dst ∈ объявленных маршрутов;
//   - сервер отправляет пакеты с dst ∈ адресов, выданных клиенту.
//
// Conn проверяет эти правила на приёме и на отправке — пакеты,
// не проходящие проверку, отбрасываются.
package masque
