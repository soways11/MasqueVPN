package masque

import (
	"crypto/rand"
	"net"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Длина Connection ID сервера — часть отпечатка серверной стороны, которую
// видно в открытую.
//
// quic-go берёт по умолчанию 4 байта. Длина попадает в поле SCID заголовка
// Initial-пакета сервера, то есть читается наблюдателем при каждом
// рукопожатии; дальше поле DCID ровно этой длины едет в КАЖДОМ пакете
// клиента. Живые серверы HTTP/3 используют 8 и больше (у Google — 8, у
// Cloudflare — 8–20), так что четырёхбайтный CID — узкая примета
// реализации: она не зависит ни от TLS-отпечатка, ни от транспортных
// параметров, и по ней сервер на quic-go отличается от CDN одним пакетом.
//
// Проверено пассивным наблюдателем на стенде (test/e2e/dpitap): до
// исправления в рукопожатии стояло SCID=4.
const DefaultConnectionIDLength = 8

// randomCID выдаёт случайные Connection ID заданной длины.
type randomCID struct{ n int }

func (g randomCID) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, g.n)
	if _, err := rand.Read(b); err != nil {
		return quic.ConnectionID{}, err
	}
	return quic.ConnectionIDFromBytes(b), nil
}

func (g randomCID) ConnectionIDLen() int { return g.n }

// ServeUDP обслуживает HTTP/3-сервер на готовом сокете, задавая длину
// Connection ID (0 — DefaultConnectionIDLength, отрицательное — оставить
// умолчание quic-go).
//
// Это то же, что http3.Server.Serve, но со своим quic.Transport: длина
// Connection ID задаётся только там, через http3.Server до неё не добраться.
// Сокет не закрывается — он принадлежит вызывающему.
func ServeUDP(srv *http3.Server, pc net.PacketConn, cidLen int) error {
	if cidLen == 0 {
		cidLen = DefaultConnectionIDLength
	}
	tr := &quic.Transport{Conn: pc}
	if cidLen > 0 {
		tr.ConnectionIDGenerator = randomCID{cidLen}
	}
	// Stateless reset — то, чем настоящий сервер отвечает на пакет с
	// незнакомым Connection ID (RFC 9000, §10.3). Без ключа quic-go молчит,
	// а молчание тут как раз и заметно: у живого HTTP/3-сервера на такой
	// пакет приходит ответ, и пробер, поймавший наш Connection ID, отличает
	// нас одним пакетом. Заодно в транспортных параметрах появляется
	// stateless_reset_token, который мы до сих пор только объявляли в
	// профиле, но не отправляли.
	var key quic.StatelessResetKey
	if _, err := rand.Read(key[:]); err == nil {
		tr.StatelessResetKey = &key
	}
	defer tr.Close()

	var quicConf *quic.Config
	if srv.QUICConfig != nil {
		quicConf = srv.QUICConfig.Clone()
	} else {
		quicConf = &quic.Config{}
	}
	if srv.EnableDatagrams {
		quicConf.EnableDatagrams = true
	}
	ln, err := tr.ListenEarly(srv.TLSConfig, quicConf)
	if err != nil {
		return err
	}
	defer ln.Close()
	return srv.ServeListener(ln)
}
