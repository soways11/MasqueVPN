package main

// Резервная копия реестра клиентов.
//
// # Зачем
//
// В `clients.json` лежат ключи всех клиентов. Восстановить его неоткуда:
// ключи генерируются при выдаче и больше нигде не хранятся — ни у сервера,
// ни в базе. Потеря файла означает, что доступ теряют все разом, и чинится
// это только перевыдачей каждому.
//
// Защиты от этого не было никакой. Причём самый вероятный способ потерять
// файл — не отказ диска, а человек: переустановка, `rm` не в том каталоге,
// неудачная миграция на другой сервер.
//
// # Что входит в копию
//
// Реестр и файл учёта расхода — вместе, одним файлом. Порознь они
// расходятся: восстановленный реестр со старым учётом означает, что квоты
// начнут считаться заново, и клиент, исчерпавший месячную, получит её
// обратно.
//
// Копия — обычный JSON, не архив: её можно открыть и посмотреть, что внутри,
// а при нужде вытащить один ключ руками, не имея под рукой masquevpn.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// backupFile — формат резервной копии.
type backupFile struct {
	// Kind и Version — чтобы при восстановлении отличить нашу копию от
	// любого другого JSON, на который человек показал по ошибке.
	Kind    string `json:"kind"`
	Version int    `json:"version"`
	Created string `json:"created"`
	// Source — откуда снята: помогает понять, тот ли это сервер.
	Source string `json:"source"`

	Clients json.RawMessage `json:"clients"`
	Usage   json.RawMessage `json:"usage,omitempty"`
}

const backupKind = "masquevpn-clients-backup"

// legacyBackupKind — метка копий, сделанных до переименования проекта.
// Такие копии лежат у людей годами, и восстановление обязано их принимать.
const legacyBackupKind = "govpn-clients-backup"

// makeBackup снимает копию реестра и учёта в файл out.
func makeBackup(w io.Writer, regPath, usagePath, out string) int {
	regRaw, err := os.ReadFile(regPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients backup:", err)
		return 1
	}
	// Реестр должен быть разборчивым: копировать испорченный файл — значит
	// сохранить поломку и узнать о ней при восстановлении.
	if !json.Valid(regRaw) {
		fmt.Fprintf(os.Stderr, "vpnserver clients backup: %s — не разбирается как JSON, копия не снята\n", regPath)
		return 1
	}

	b := backupFile{
		Kind:    backupKind,
		Version: 1,
		Created: time.Now().UTC().Format(time.RFC3339),
		Source:  regPath,
		Clients: regRaw,
	}
	if usageRaw, err := os.ReadFile(usagePath); err == nil && json.Valid(usageRaw) {
		b.Usage = usageRaw
	}

	if out == "" {
		out = regPath + "." + time.Now().Format("20060102-150405") + ".backup"
	}
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients backup:", err)
		return 1
	}
	if err := writePrivate(out, append(raw, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients backup:", err)
		return 1
	}

	n := countClients(regRaw)
	fmt.Fprintf(w, "копия снята: %s (права 0600)\n", out)
	fmt.Fprintf(w, "клиентов в копии: %d%s\n", n, usageWord(b.Usage != nil))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "В копии лежат ключи всех клиентов — храните её так же, как сам реестр.")
	fmt.Fprintln(w, "Восстановление: vpnserver clients restore -from", out)
	return 0
}

// restoreBackup возвращает реестр и учёт из копии.
//
// Перед записью текущие файлы сохраняются рядом: восстановление «не из той»
// копии — такая же потеря доступа, как и та, от которой мы защищаемся.
func restoreBackup(w io.Writer, regPath, usagePath, from string) int {
	raw, err := os.ReadFile(from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients restore:", err)
		return 1
	}
	var b backupFile
	if err := json.Unmarshal(raw, &b); err != nil {
		fmt.Fprintf(os.Stderr, "vpnserver clients restore: %s не похож на копию masquevpn: %v\n", from, err)
		return 1
	}
	if b.Kind != backupKind && b.Kind != legacyBackupKind {
		fmt.Fprintf(os.Stderr, "vpnserver clients restore: %s — не копия реестра masquevpn\n", from)
		return 1
	}
	if !json.Valid(b.Clients) || countClients(b.Clients) == 0 {
		fmt.Fprintf(os.Stderr, "vpnserver clients restore: в копии нет ни одного клиента, не восстанавливаю\n")
		return 1
	}

	if err := keepAside(regPath); err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients restore:", err)
		return 1
	}
	if err := keepAside(usagePath); err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients restore:", err)
		return 1
	}
	if err := writePrivate(regPath, b.Clients); err != nil {
		fmt.Fprintln(os.Stderr, "vpnserver clients restore:", err)
		return 1
	}
	if b.Usage != nil {
		if err := writePrivate(usagePath, b.Usage); err != nil {
			fmt.Fprintln(os.Stderr, "vpnserver clients restore:", err)
			return 1
		}
	}

	fmt.Fprintf(w, "восстановлено из %s (снята %s)\n", from, b.Created)
	fmt.Fprintf(w, "клиентов: %d%s\n", countClients(b.Clients), usageWord(b.Usage != nil))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Прежние файлы сохранены рядом с расширением .before-restore")
	fmt.Fprintln(w, "Сервер перечитает реестр сам в течение нескольких секунд.")
	return 0
}

// keepAside сохраняет существующий файл рядом, чтобы неудачное
// восстановление можно было отменить. Отсутствие файла — не ошибка: мы как
// раз могли его и потерять.
func keepAside(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return writePrivate(path+".before-restore", raw)
}

// writePrivate пишет файл с правами 0600: внутри ключи.
func writePrivate(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

// countClients считает записи в реестре, не разбирая его целиком: формат
// реестра — дело пакета clients, а здесь нужно лишь «сколько их».
func countClients(raw json.RawMessage) int {
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		return len(asArray)
	}
	var asObject map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObject); err == nil {
		if inner, ok := asObject["clients"]; ok {
			return countClients(inner)
		}
		return len(asObject)
	}
	return 0
}

func usageWord(has bool) string {
	if has {
		return ", учёт расхода тоже"
	}
	return " (учёта расхода в копии нет)"
}
