package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Профиль, снятый с живого сервера, неполон по устройству: часть того, чем
// отличается сервер, транспортными параметрами не объявляется и клиенту не
// видна. Тесты ниже стерегут места, где такая неполнота молча меняла бы
// поведение нашего сервера.

// Настоящая запись с cloudflare-quic.com (24.09.2026). Ровно то, что кладёт
// fpserver: ни размера пакета, ни длины Connection ID в ней нет.
const capturedCloudflare = `{
  "source": "cloudflare-quic.com:443",
  "captured_at": "2026-09-24T15:55:30Z",
  "max_idle_timeout_ms": 180000,
  "initial_max_data": 10485760,
  "initial_max_stream_data": 1048576,
  "initial_max_streams_bidi": 100,
  "initial_max_streams_uni": 3
}`

// И с www.google.com — там начальные окна крошечные.
const capturedGoogle = `{
  "source": "www.google.com:443",
  "captured_at": "2026-09-24T15:55:30Z",
  "max_idle_timeout_ms": 240000,
  "initial_max_data": 196608,
  "initial_max_stream_data": 131072,
  "initial_max_streams_bidi": 100,
  "initial_max_streams_uni": 103,
  "stateless_reset": true
}`

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "srv.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCapturedProfileKeepsPacketSize — снятый профиль не роняет размер пакета
// до умолчания quic-go.
//
// Размер пакета не объявляется в транспортных параметрах, поэтому в файле от
// fpserver его нет вовсе. Нулевое поле означало бы для quic-go 1280 вместо
// наших 1350 — потолок датаграммы падает примерно на 70 байт, и происходит
// это молча. Место тонкое: на нём проект уже ловил чёрную дыру MTU.
func TestCapturedProfileKeepsPacketSize(t *testing.T) {
	p, err := LoadServerProfile(writeProfile(t, capturedCloudflare))
	if err != nil {
		t.Fatal(err)
	}
	if p.InitialPacketSize != DefaultInitialPacketSize {
		t.Errorf("размер пакета %d, ожидался %d", p.InitialPacketSize, DefaultInitialPacketSize)
	}
	if got := p.QUICConfig().InitialPacketSize; got != DefaultInitialPacketSize {
		t.Errorf("в quic.Config ушёл размер %d", got)
	}
}

// TestCapturedProfileKeepsConnectionID — и длину Connection ID тоже.
//
// Ноль вернул бы 4 байта quic-go: та самая длина, по которой сервер на
// quic-go отличается от живого CDN одним пакетом (она едет в каждом пакете
// клиента).
func TestCapturedProfileKeepsConnectionID(t *testing.T) {
	p, err := LoadServerProfile(writeProfile(t, capturedCloudflare))
	if err != nil {
		t.Fatal(err)
	}
	if p.CIDLength() != DefaultConnectionIDLength {
		t.Errorf("длина Connection ID %d, ожидалась %d", p.CIDLength(), DefaultConnectionIDLength)
	}
}

// TestCapturedProfileKeepsDatagrams — датаграммы включены, откуда бы профиль
// ни взялся. Ни Cloudflare, ни Google их не объявляют, так что из снятого
// профиля они прийти не могут в принципе, а без них нет CONNECT-IP.
func TestCapturedProfileKeepsDatagrams(t *testing.T) {
	for name, body := range map[string]string{"cloudflare": capturedCloudflare, "google": capturedGoogle} {
		p, err := LoadServerProfile(writeProfile(t, body))
		if err != nil {
			t.Fatal(err)
		}
		if !p.QUICConfig().EnableDatagrams {
			t.Errorf("%s: датаграммы выключены — туннеля не будет", name)
		}
	}
}

// TestCapturedProfileDoesNotThrottle — маленькие начальные окна из профиля не
// становятся потолком.
//
// У www.google.com начальное окно соединения 192 КиБ. Если сделать его же
// потолком, туннель упрётся в flow control: при 50 мс кругового времени это
// порядка 30 Мбит/с вместо сотен. А наружу потолок не виден — он проявляется
// только в зашифрованных MAX_DATA, — то есть занижать его незачем.
func TestCapturedProfileDoesNotThrottle(t *testing.T) {
	p, err := LoadServerProfile(writeProfile(t, capturedGoogle))
	if err != nil {
		t.Fatal(err)
	}
	c := p.QUICConfig()

	// Объявляем то, что сняли.
	if c.InitialConnectionReceiveWindow != 196608 {
		t.Errorf("начальное окно соединения %d, в профиле 196608", c.InitialConnectionReceiveWindow)
	}
	if c.InitialStreamReceiveWindow != 131072 {
		t.Errorf("начальное окно потока %d, в профиле 131072", c.InitialStreamReceiveWindow)
	}
	// А расти даём куда больше.
	if c.MaxConnectionReceiveWindow < defaultMaxConnWindow {
		t.Errorf("потолок окна соединения %d — туннель задушен профилем", c.MaxConnectionReceiveWindow)
	}
	if c.MaxStreamReceiveWindow < defaultMaxStreamWindow {
		t.Errorf("потолок окна потока %d — туннель задушен профилем", c.MaxStreamReceiveWindow)
	}
}

// TestCapturedProfileKeepsLargeWindows — щедрый профиль не урезается нашим
// минимумом: если сервер объявляет больше, объявляем больше и мы.
func TestCapturedProfileKeepsLargeWindows(t *testing.T) {
	p := ServerProfile{
		MaxIdleTimeoutMS:     180000,
		InitialMaxData:       64 * 1024 * 1024,
		InitialMaxStreamData: 32 * 1024 * 1024,
	}
	c := p.QUICConfig()
	if c.MaxConnectionReceiveWindow != 64*1024*1024 {
		t.Errorf("потолок окна соединения %d, ожидалось 64 МиБ", c.MaxConnectionReceiveWindow)
	}
	if c.MaxStreamReceiveWindow != 32*1024*1024 {
		t.Errorf("потолок окна потока %d, ожидалось 32 МиБ", c.MaxStreamReceiveWindow)
	}
}

// TestCapturedProfileIdleTimeout — время простоя переносится как снято.
// У живых серверов это 3–4 минуты против 30 секунд нашей эвристики.
func TestCapturedProfileIdleTimeout(t *testing.T) {
	p, err := LoadServerProfile(writeProfile(t, capturedCloudflare))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.QUICConfig().MaxIdleTimeout; got != 180*time.Second {
		t.Errorf("время простоя %v, в профиле 180 с", got)
	}
	if h := CDNLike().MaxIdleTimeoutMS; h == p.MaxIdleTimeoutMS {
		t.Errorf("эвристика и снятый профиль совпали (%d мс) — тест перестал что-либо значить", h)
	}
}

// TestEmbeddedProfileIsCaptured — встроенный профиль это СНЯТОЕ, а не
// эвристика, и он пригоден к работе.
//
// Зашитый в бинарник файл легко разъехаться с кодом: его никто не читает,
// пока не запустят сервер. Тест читает его тем же путём, что и сервер.
func TestEmbeddedProfileIsCaptured(t *testing.T) {
	p := Captured()
	if err := p.Valid(); err != nil {
		t.Fatalf("встроенный профиль негоден: %v", err)
	}
	if p.Source == CDNLike().Source {
		t.Fatal("встроен эвристический профиль вместо снятого")
	}
	t.Logf("встроено: %s", p.Source)

	// Поля, которые снять нельзя, должны быть на месте — иначе сервер
	// молча возьмёт умолчания quic-go.
	if p.InitialPacketSize != DefaultInitialPacketSize {
		t.Errorf("размер пакета %d, ожидался %d", p.InitialPacketSize, DefaultInitialPacketSize)
	}
	if p.CIDLength() != DefaultConnectionIDLength {
		t.Errorf("длина Connection ID %d, ожидалась %d", p.CIDLength(), DefaultConnectionIDLength)
	}

	c := p.QUICConfig()
	if !c.EnableDatagrams {
		t.Error("датаграммы выключены — туннеля не будет")
	}
	// И он должен отличаться от эвристики, иначе подмена бессмысленна.
	h := CDNLike()
	if p.MaxIdleTimeoutMS == h.MaxIdleTimeoutMS && p.InitialMaxData == h.InitialMaxData {
		t.Fatal("встроенный профиль совпал с эвристикой")
	}
	t.Logf("простой %d мс против %d мс у эвристики", p.MaxIdleTimeoutMS, h.MaxIdleTimeoutMS)
}
