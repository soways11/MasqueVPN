package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ALPNChallenge — ALPN проверки tls-alpn-01 (дубль константы из acme, чтобы
// пакет не зависел от проверяемого кода).
const ALPNChallenge = "acme-tls/1"

// Package acmetest — минимальный удостоверяющий центр ACME (RFC 8555) для тестов.
//
// Зачем он: проверить выпуск сертификата иначе нельзя — настоящий
// Let's Encrypt требует публичного домена и сети, а без реального обмена
// «каталог → аккаунт → заказ → проверка → finalize → сертификат» слова
// «ACME сделан» ничего не стоят. Здесь реализовано ровно столько, сколько
// использует наш клиент, и главное — НАСТОЯЩАЯ проверка tls-alpn-01:
// центр сам подключается к слушателю сервера с ALPN «acme-tls/1» и
// сверяет метку в проверочном сертификате.
//
// Подписи JWS не проверяются: это тестовый центр, его задача — воспроизвести
// последовательность обмена и проверку владения доменом, а не быть
// удостоверяющим центром.

// acmeIdentifierOID — расширение сертификата с меткой проверки (RFC 8737).
var acmeIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// CA — удостоверяющий центр: выдаёт сертификаты и по-настоящему проверяет
// владение доменом, подключаясь к слушателю проверяемого сервера.
type CA struct {
	baseURL string
	caKey   *ecdsa.PrivateKey
	caCert  *x509.Certificate
	caPEM   []byte
	roots   *x509.CertPool
	nonce   int
	mu      sync.Mutex
	thumb   string            // отпечаток ключа аккаунта клиента
	tokens  map[string]string // authz id → token
	names   map[string]string // authz id → проверяемое имя
	valid   map[string]bool
	certs   map[string][]byte // order id → PEM-цепочка
	target  string            // куда ходить на проверку (host:port)
	issued  int
	failNow bool // отвечать отказом на любой заказ
	// Lifetime — срок выпускаемого сертификата.
	Lifetime time.Duration
	// Logf — куда писать ход обмена; nil — молча.
	Logf func(string, ...any)
}

// New создаёт центр. baseURL — адрес, по которому он будет доступен клиенту
// (например http://127.0.0.1:8081): он подставляется в ссылки каталога.
func New(baseURL string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "masquevpn test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return &CA{
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		caKey:    key,
		caCert:   caCert,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		roots:    roots,
		tokens:   map[string]string{},
		names:    map[string]string{},
		valid:    map[string]bool{},
		certs:    map[string][]byte{},
		Lifetime: 90 * 24 * time.Hour,
	}, nil
}

// DirectoryURL — адрес каталога для клиента.
func (ca *CA) DirectoryURL() string { return ca.baseURL + "/directory" }

// Roots — корневой сертификат центра (для клиентов, которые должны ему верить).
func (ca *CA) Roots() *x509.CertPool { return ca.roots }

// PEM — корневой сертификат в PEM.
func (ca *CA) PEM() []byte { return ca.caPEM }

// Handler — обработчик HTTP центра.
func (ca *CA) Handler() http.Handler { return ca.routes() }

// SetTarget задаёт адрес (host:port), куда центр идёт на проверку владения.
func (ca *CA) SetTarget(addr string) { ca.mu.Lock(); ca.target = addr; ca.mu.Unlock() }

// SetFail заставляет центр отказывать в заказах.
func (ca *CA) SetFail(v bool) { ca.mu.Lock(); ca.failNow = v; ca.mu.Unlock() }

// Issued — сколько сертификатов выдано.
func (ca *CA) Issued() int { ca.mu.Lock(); defer ca.mu.Unlock(); return ca.issued }

func (ca *CA) logf(format string, args ...any) {
	if ca.Logf != nil {
		ca.Logf(format, args...)
	}
}

func (ca *CA) nextNonce() string {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.nonce++
	return fmt.Sprintf("nonce-%d", ca.nonce)
}

func (ca *CA) routes() http.Handler {
	mux := http.NewServeMux()
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ca.logf("[CA] %s %s", r.Method, r.URL.Path)
			w.Header().Set("Replay-Nonce", ca.nextNonce())
			w.Header().Set("Cache-Control", "no-store")
			h(w, r)
		}
	}
	mux.HandleFunc("/directory", wrap(func(w http.ResponseWriter, _ *http.Request) {
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"newNonce":   ca.url("/new-nonce"),
			"newAccount": ca.url("/new-account"),
			"newOrder":   ca.url("/new-order"),
			"revokeCert": ca.url("/revoke"),
			"keyChange":  ca.url("/key-change"),
			"meta":       map[string]any{"termsOfService": ca.url("/tos")},
		})
	}))
	mux.HandleFunc("/new-nonce", wrap(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/new-account", wrap(func(w http.ResponseWriter, r *http.Request) {
		hdr, _ := ca.readJWS(r)
		if jwk, ok := hdr["jwk"].(map[string]any); ok {
			ca.mu.Lock()
			ca.thumb = jwkThumbprint(jwk)
			ca.mu.Unlock()
		}
		w.Header().Set("Location", ca.url("/account/1"))
		ca.writeJSON(w, http.StatusCreated, map[string]any{"status": "valid"})
	}))
	mux.HandleFunc("/new-order", wrap(func(w http.ResponseWriter, r *http.Request) {
		_, payload := ca.readJWS(r)
		ca.mu.Lock()
		if ca.failNow {
			ca.mu.Unlock()
			ca.writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"type": "urn:ietf:params:acme:error:rateLimited", "detail": "тестовый отказ",
			})
			return
		}
		ca.mu.Unlock()

		var req struct {
			Identifiers []struct{ Type, Value string } `json:"identifiers"`
		}
		_ = json.Unmarshal(payload, &req)
		if len(req.Identifiers) == 0 {
			http.Error(w, "нет идентификаторов", http.StatusBadRequest)
			return
		}
		id := fmt.Sprintf("%d", time.Now().UnixNano())
		ca.mu.Lock()
		ca.tokens[id] = "token-" + id
		ca.names[id] = req.Identifiers[0].Value
		ca.mu.Unlock()

		w.Header().Set("Location", ca.url("/order/"+id))
		ca.writeJSON(w, http.StatusCreated, map[string]any{
			"status":         "pending",
			"identifiers":    req.Identifiers,
			"authorizations": []string{ca.url("/authz/" + id)},
			"finalize":       ca.url("/finalize/" + id),
			"expires":        time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	mux.HandleFunc("/authz/", wrap(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/authz/")
		ca.mu.Lock()
		token, ok := ca.tokens[id]
		valid := ca.valid[id]
		ca.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		status := "pending"
		chalStatus := "pending"
		if valid {
			status, chalStatus = "valid", "valid"
		}
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status":     status,
			"identifier": map[string]string{"type": "dns", "value": "unused"},
			"challenges": []map[string]any{{
				"type": "tls-alpn-01", "url": ca.url("/chal/" + id),
				"token": token, "status": chalStatus,
			}},
		})
	}))
	mux.HandleFunc("/chal/", wrap(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/chal/")
		ca.mu.Lock()
		token, ok := ca.tokens[id]
		target, thumb, name := ca.target, ca.thumb, ca.names[id]
		ca.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		// Настоящая проверка владения доменом: идём на слушатель сервера.
		if err := ca.validate(target, name, token, thumb); err != nil {
			ca.writeJSON(w, http.StatusOK, map[string]any{
				"type": "tls-alpn-01", "url": ca.url("/chal/" + id), "token": token,
				"status": "invalid",
				"error":  map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": err.Error()},
			})
			return
		}
		ca.mu.Lock()
		ca.valid[id] = true
		ca.mu.Unlock()
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"type": "tls-alpn-01", "url": ca.url("/chal/" + id), "token": token, "status": "valid",
		})
	}))
	mux.HandleFunc("/finalize/", wrap(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/finalize/")
		_, payload := ca.readJWS(r)
		var req struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(payload, &req)
		der, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			http.Error(w, "битый CSR", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			http.Error(w, "неразобранный CSR", http.StatusBadRequest)
			return
		}
		chain, err := ca.sign(csr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ca.mu.Lock()
		ca.certs[id] = chain
		ca.issued++
		ca.mu.Unlock()
		w.Header().Set("Location", ca.url("/order/"+id))
		ca.writeJSON(w, http.StatusOK, map[string]any{
			"status": "valid", "certificate": ca.url("/cert/" + id),
		})
	}))
	mux.HandleFunc("/order/", wrap(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/order/")
		ca.mu.Lock()
		_, done := ca.certs[id]
		ready := ca.valid[id]
		ca.mu.Unlock()
		// RFC 8555: пока проверки не пройдены — pending; когда пройдены, но
		// сертификат ещё не заказан — ready (клиент ждёт именно этого, чтобы
		// отправить CSR); после finalize — valid со ссылкой на сертификат.
		body := map[string]any{"status": "pending", "finalize": ca.url("/finalize/" + id)}
		switch {
		case done:
			body = map[string]any{"status": "valid", "certificate": ca.url("/cert/" + id)}
		case ready:
			body = map[string]any{"status": "ready", "finalize": ca.url("/finalize/" + id)}
		}
		ca.writeJSON(w, http.StatusOK, body)
	}))
	mux.HandleFunc("/cert/", wrap(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/cert/")
		ca.mu.Lock()
		chain := ca.certs[id]
		ca.mu.Unlock()
		if chain == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(chain)
	}))
	return mux
}

func (ca *CA) url(p string) string { return ca.baseURL + p }

func (ca *CA) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readJWS разбирает тело запроса: заголовок и полезную нагрузку.
// Подпись не проверяется — см. комментарий к testCA.
func (ca *CA) readJWS(r *http.Request) (map[string]any, []byte) {
	var body struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, nil
	}
	hdrRaw, _ := base64.RawURLEncoding.DecodeString(body.Protected)
	var hdr map[string]any
	_ = json.Unmarshal(hdrRaw, &hdr)
	payload, _ := base64.RawURLEncoding.DecodeString(body.Payload)
	return hdr, payload
}

// validate — проверка tls-alpn-01: подключаемся к слушателю сервера с ALPN
// «acme-tls/1» и сверяем метку в проверочном сертификате.
func (ca *CA) validate(target, name, token, thumb string) error {
	if target == "" {
		return fmt.Errorf("некуда идти на проверку")
	}
	conn, err := tls.Dial("tcp", target, &tls.Config{
		ServerName:         name,
		NextProtos:         []string{ALPNChallenge},
		InsecureSkipVerify: true, // проверочный сертификат самоподписанный — так и задумано
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return fmt.Errorf("соединение для проверки: %w", err)
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.NegotiatedProtocol != ALPNChallenge {
		return fmt.Errorf("сервер не согласовал %s (получено %q)", ALPNChallenge, st.NegotiatedProtocol)
	}
	if len(st.PeerCertificates) == 0 {
		return fmt.Errorf("сервер не прислал сертификат")
	}
	cert := st.PeerCertificates[0]
	var got []byte
	for _, e := range cert.Extensions {
		if e.Id.Equal(acmeIdentifierOID) {
			got = e.Value
		}
	}
	if got == nil {
		return fmt.Errorf("в проверочном сертификате нет метки %v", acmeIdentifierOID)
	}
	want := sha256.Sum256([]byte(token + "." + thumb))
	wantDER, err := asn1.Marshal(want[:])
	if err != nil {
		return err
	}
	if string(got) != string(wantDER) {
		return fmt.Errorf("метка не совпала: % x против % x", got, wantDER)
	}
	return nil
}

// sign выпускает сертификат по запросу.
func (ca *CA) sign(csr *x509.CertificateRequest) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 96))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: firstName(csr)},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(ca.Lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, csr.PublicKey, ca.caKey)
	if err != nil {
		return nil, err
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(out, ca.caPEM...), nil
}

func firstName(csr *x509.CertificateRequest) string {
	if len(csr.DNSNames) > 0 {
		return csr.DNSNames[0]
	}
	return csr.Subject.CommonName
}

// jwkThumbprint — отпечаток ключа аккаунта (RFC 7638): SHA-256 от
// канонического JSON с полями в алфавитном порядке.
func jwkThumbprint(jwk map[string]any) string {
	var canon string
	switch jwk["kty"] {
	case "EC":
		canon = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk["crv"], jwk["x"], jwk["y"])
	case "RSA":
		canon = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	default:
		return ""
	}
	sum := sha256.Sum256([]byte(canon))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
