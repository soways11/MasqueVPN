package main

import (
	"log/slog"
	"time"

	"github.com/soways11/masquevpn/internal/clients"
	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/masque"
)

// Подключение реестра клиентов к серверу: поиск ключа, политика, учёт и
// отзыв. Сам реестр не знает ни про masque, ни про сервер, а сервер не знает,
// что реестр — это файл.

// openClients открывает реестр и учёт, если в конфигурации задан clients_file.
// Возвращает (nil, nil, nil), если режим ключей по клиентам не включён.
func openClients(cfg *config.Server, log *slog.Logger) (*clients.Registry, *clients.Accountant, error) {
	if cfg.ClientsFile == "" {
		return nil, nil, nil
	}
	reg, err := clients.Open(cfg.ClientsFile)
	if err != nil {
		return nil, nil, err
	}
	acc, err := clients.NewAccountant(cfg.UsagePath(), reg)
	if err != nil {
		return nil, nil, err
	}
	if reg.Len() == 0 {
		// Пустой реестр — это сервер, к которому никто не может подключиться.
		// Молчать об этом нельзя: снаружи он выглядит работающим, а клиенты
		// получают тот же 404, что и посторонние.
		log.Warn("реестр клиентов пуст — подключиться не сможет никто; "+
			"добавьте клиента командой vpnserver clients add",
			"файл", cfg.ClientsFile)
	} else {
		log.Info("реестр клиентов", "файл", cfg.ClientsFile, "клиентов", reg.Len(),
			"учёт", cfg.UsagePath())
	}
	return reg, acc, nil
}

// policyOf приводит учёт к интерфейсу masque.Policy. Отдельная функция, а не
// прямое присваивание: nil-интерфейс с nil-значением внутри — не nil, и
// masque честно позвал бы политику у несуществующего реестра.
func policyOf(acc *clients.Accountant) masque.Policy {
	if acc == nil {
		return nil
	}
	return acc
}

// watchClients следит за файлом реестра и за квотами: закрывает сессии тех,
// кого удалили, выключили или кто вышел за квоту, и периодически сохраняет
// расход. Возвращает функцию остановки.
func watchClients(h *masque.Handler, reg *clients.Registry, acc *clients.Accountant,
	cfg *config.Server, log *slog.Logger) func() {

	stop := make(chan struct{})
	done := make(chan struct{})

	reload := time.Duration(cfg.ClientsReload)
	if reload <= 0 {
		reload = 10 * time.Second
	}

	go func() {
		defer close(done)
		reg.Watch(stop, reload, func(revoked []string) {
			for _, id := range revoked {
				if n := h.CloseClient(id); n > 0 {
					log.Info("доступ отозван, сессии закрыты", "клиент", id, "сессий", n)
				} else {
					log.Info("доступ отозван", "клиент", id)
				}
			}
		}, func(err error) {
			// Ошибка чтения реестра НЕ отключает никого: битый или временно
			// недоступный файл не повод обрубить связь всем разом. Работаем
			// на прежнем составе и жалуемся в журнал.
			log.Error("реестр клиентов не перечитан, работаю на прежнем составе", "err", err)
		})
	}()

	go func() {
		// Квота должна закрывать и уже открытые сессии: сессию открыли до
		// исчерпания, и без этого она качала бы дальше сколько угодно.
		t := time.NewTicker(masque.DefaultAccountInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				for _, id := range acc.OverQuota() {
					if n := h.CloseClient(id); n > 0 {
						u := acc.Usage(id)
						log.Info("квота исчерпана, сессии закрыты",
							"клиент", id, "сессий", n, "израсходовано", u.Bytes)
					}
				}
			}
		}
	}()

	go acc.Run(stop, 30*time.Second, func(err error) {
		log.Error("не сохранён учёт расхода", "err", err)
	})

	return func() {
		close(stop)
		<-done
		if err := acc.Save(); err != nil {
			log.Error("не сохранён учёт расхода", "err", err)
		}
	}
}
