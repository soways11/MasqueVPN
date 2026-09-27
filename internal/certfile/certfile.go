// Package certfile — сертификат из файлов, который подхватывается заново,
// когда файлы на диске меняются.
//
// Зачем. Когда сертификат берётся из cert_file/key_file, его обновляет
// кто-то другой: certbot, acme.sh, соседний nginx. Обновляет молча — просто
// перезаписывает файлы раз в два месяца. Сервер, прочитавший их один раз при
// старте, будет отдавать прежний сертификат до перезапуска, а через три
// месяца — просроченный. Снаружи это выглядит как внезапно сломавшийся домен,
// и «лечится» перезапуском, о котором надо догадаться.
//
// Поэтому файлы перечитываются по изменению: время правки и размер
// проверяются не чаще раза в интервал, и только при расхождении делается
// повторное чтение.
//
// Важная тонкость: во время обновления файлы бывают несогласованы — новый
// сертификат уже записан, ключ ещё нет. Такое чтение не должно ронять
// сервер: при ошибке остаётся прежняя пара, а в журнал уходит
// предупреждение. Следующая проверка подберёт уже согласованную.
package certfile

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// DefaultCheckInterval — как часто смотреть, не изменились ли файлы.
// Обновление сертификата — событие раз в два месяца, так что чаще незачем.
//
// Переменная, а не константа, только ради тестов: проверить, что сервер
// действительно подхватывает новый сертификат, иначе можно было бы лишь
// подождав полминуты в каждом таком тесте.
var DefaultCheckInterval = 30 * time.Second

type stamp struct {
	mod  time.Time
	size int64
}

// Reloader отдаёт сертификат из пары файлов и следит за их изменением.
type Reloader struct {
	certPath, keyPath string
	every             time.Duration
	log               *slog.Logger

	now func() time.Time

	mu      sync.RWMutex
	cert    *tls.Certificate
	cs, ks  stamp
	checked time.Time
	reloads int
}

// New читает пару файлов и возвращает загрузчик. Ошибка первого чтения —
// это ошибка запуска: сервер без сертификата бесполезен.
func New(certPath, keyPath string, log *slog.Logger) (*Reloader, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	r := &Reloader{
		certPath: certPath, keyPath: keyPath,
		every: DefaultCheckInterval, log: log, now: time.Now,
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	r.checked = r.now()
	return r, nil
}

// load читает пару и запоминает отметки файлов. Вызывается под mu или до
// публикации значения.
func (r *Reloader) load() error {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return fmt.Errorf("сертификат: %w", err)
	}
	cs, err := stampOf(r.certPath)
	if err != nil {
		return err
	}
	ks, err := stampOf(r.keyPath)
	if err != nil {
		return err
	}
	r.cert, r.cs, r.ks = &cert, cs, ks
	return nil
}

func stampOf(path string) (stamp, error) {
	st, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{mod: st.ModTime(), size: st.Size()}, nil
}

// changed сообщает, отличаются ли файлы от прочитанных.
func (r *Reloader) changed() bool {
	cs, err := stampOf(r.certPath)
	if err != nil {
		return false // файл пропал — работаем на прежнем, жалуемся при чтении
	}
	ks, err := stampOf(r.keyPath)
	if err != nil {
		return false
	}
	return cs != r.cs || ks != r.ks
}

// Certificate возвращает текущий сертификат, при необходимости перечитав файлы.
func (r *Reloader) Certificate() *tls.Certificate {
	r.mu.RLock()
	cert, checked := r.cert, r.checked
	r.mu.RUnlock()

	if r.now().Sub(checked) < r.every {
		return cert
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Пока ждали замок, мог проверить кто-то другой.
	if r.now().Sub(r.checked) < r.every {
		return r.cert
	}
	r.checked = r.now()
	if !r.changed() {
		return r.cert
	}
	prev := r.cert
	if err := r.load(); err != nil {
		// Скорее всего файлы обновляются прямо сейчас и рассогласованы.
		// Остаёмся на прежней паре: отдать половину новой нельзя, а падать
		// из-за чужого обновления — тем более.
		r.cert = prev
		r.log.Warn("сертификат изменился, но не читается — остаюсь на прежнем",
			"err", err, "файл", r.certPath)
		return r.cert
	}
	r.reloads++
	r.log.Info("сертификат перечитан", "файл", r.certPath)
	return r.cert
}

// GetCertificate годится для tls.Config.GetCertificate.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.Certificate(), nil
}

// Reloads — сколько раз сертификат перечитывался (для тестов и журнала).
func (r *Reloader) Reloads() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reloads
}
