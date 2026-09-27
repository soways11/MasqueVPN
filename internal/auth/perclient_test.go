package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"testing"
)

// Проверки режима «ключ на клиента»: подпись проверяется ключом ТОГО клиента,
// чей псевдоним стоит в токене.

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newID(t *testing.T) []byte {
	t.Helper()
	id := make([]byte, ClientIDLen)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// клиентская сторона: свой псевдоним и свой ключ.
func newClient(t *testing.T, id, key []byte) *Authenticator {
	t.Helper()
	a, err := New(key, Options{ClientIDExact: id})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(t *testing.T, a *Authenticator) *http.Request {
	t.Helper()
	h, err := a.Header()
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header = h
	return r
}

func TestPerClientKeys(t *testing.T) {
	idA, keyA := newID(t), newKey(t)
	idB, keyB := newID(t), newKey(t)
	keys := map[string][]byte{
		hex.EncodeToString(idA): keyA,
		hex.EncodeToString(idB): keyB,
	}
	srv, err := New(nil, Options{Keys: func(id string) ([]byte, bool) {
		k, ok := keys[id]
		return k, ok
	}})
	if err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]*Authenticator{
		"A": newClient(t, idA, keyA),
		"B": newClient(t, idB, keyB),
	} {
		got, _, ok := srv.Identify(request(t, c))
		if !ok {
			t.Fatalf("клиент %s не прошёл со своим ключом", name)
		}
		if want := c.ClientID(); got != want {
			t.Fatalf("клиент %s опознан как %s", want, got)
		}
	}

	// Главное свойство: чужим ключом под своим псевдонимом не зайти.
	// Без него личные ключи были бы декорацией — подошёл бы любой.
	imposter := newClient(t, idA, keyB)
	if _, _, ok := srv.Identify(request(t, imposter)); ok {
		t.Fatal("клиент A прошёл с ключом клиента B")
	}

	// И под чужим ключом со своим псевдонимом — тоже нет.
	stranger := newClient(t, newID(t), newKey(t))
	if _, _, ok := srv.Identify(request(t, stranger)); ok {
		t.Fatal("клиент, которого нет в реестре, прошёл")
	}
}

// Выключенный клиент — это «ключ не найден»: реестр просто перестаёт его
// отдавать. Проверяем, что сервер в этот момент действительно отказывает.
func TestDisabledClientRejected(t *testing.T) {
	id, key := newID(t), newKey(t)
	enabled := true
	srv, err := New(nil, Options{Keys: func(got string) ([]byte, bool) {
		if !enabled || got != hex.EncodeToString(id) {
			return nil, false
		}
		return key, true
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, id, key)
	if _, _, ok := srv.Identify(request(t, c)); !ok {
		t.Fatal("включённый клиент не прошёл")
	}
	enabled = false
	if _, _, ok := srv.Identify(request(t, c)); ok {
		t.Fatal("выключенный клиент прошёл")
	}
}

// Токен версии 1 не несёт псевдонима, значит выбрать ключ нечем. Принять его
// можно было бы только общим ключом — а общего в этом режиме нет.
func TestV1TokenRejectedInPerClientMode(t *testing.T) {
	id, key := newID(t), newKey(t)
	srv, err := New(nil, Options{Keys: func(string) ([]byte, bool) { return key, true }})
	if err != nil {
		t.Fatal(err)
	}
	c := newClient(t, id, key)
	tok, err := c.tokenVersion1()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.verify(tok); ok {
		t.Fatal("токен версии 1 принят в режиме ключей по клиентам")
	}
}

// Общий ключ рядом с личными — чёрный ход для отозванных: их запись из
// реестра исчезла, а общий ключ у них на руках остался.
func TestSharedKeyWithPerClientRejected(t *testing.T) {
	_, err := New(newKey(t), Options{Keys: func(string) ([]byte, bool) { return nil, false }})
	if err == nil {
		t.Fatal("общий ключ вместе с ключами по клиентам приняты")
	}
}

// Псевдоним, выданный сервером, должен ехать в токене БАЙТ В БАЙТ: по нему
// сервер ищет запись. Свернись он хэшем, как произвольная строка, — сервер бы
// никого не нашёл.
func TestExactClientIDTravelsVerbatim(t *testing.T) {
	id := newID(t)
	c := newClient(t, id, newKey(t))
	if got, want := c.ClientID(), hex.EncodeToString(id); got != want {
		t.Fatalf("псевдоним в токене %s, выдан %s", got, want)
	}
	// А произвольная строка по-прежнему сворачивается.
	a, err := New(newKey(t), Options{ClientID: []byte("моя машина")})
	if err != nil {
		t.Fatal(err)
	}
	if a.ClientID() == hex.EncodeToString([]byte("моя машина")) {
		t.Fatal("произвольная строка не свёрнута")
	}
	if len(a.ClientID()) != ClientIDLen*2 {
		t.Fatalf("псевдоним неверной длины: %s", a.ClientID())
	}
}

func TestExactClientIDLengthChecked(t *testing.T) {
	if _, err := New(newKey(t), Options{ClientIDExact: []byte("коротко")}); err == nil {
		t.Fatal("принят псевдоним неверной длины")
	}
}

// tokenVersion1 выпускает токен старого формата (без псевдонима) — только для
// проверки того, что в режиме ключей по клиентам он отвергается.
func (a *Authenticator) tokenVersion1() (string, error) {
	nonce := make([]byte, nonceLen)
	if _, err := a.nonce(nonce); err != nil {
		return "", err
	}
	ts := a.now().Unix()
	tok := []byte{tokenV1}
	tok = binaryAppendUint64(tok, uint64(ts))
	tok = append(tok, nonce...)
	tok = append(tok, a.mac(tokenV1, ts, nil, nil, nonce)...)
	return enc.EncodeToString(tok), nil
}

func binaryAppendUint64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// Второе значение KeyLookup — это ответ «пускать или нет», и он главнее
// самого ключа. Реализация реестра вольна вернуть настоящий ключ вместе с
// отказом (например, чтобы не городить две ветки для выключенного клиента) —
// и тогда сравнение подписи сойдётся. Пускать в этом случае нельзя.
func TestLookupRefusalWinsOverKey(t *testing.T) {
	id, key := newID(t), newKey(t)
	srv, err := New(nil, Options{Keys: func(string) ([]byte, bool) {
		return key, false // ключ настоящий, но доступ закрыт
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.Identify(request(t, newClient(t, id, key))); ok {
		t.Fatal("клиент прошёл, хотя реестр ответил отказом")
	}
}
