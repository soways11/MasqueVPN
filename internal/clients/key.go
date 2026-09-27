package clients

import (
	"encoding/base64"
	"errors"
	"strings"
)

// Ключи в файле — base64. Принимаем оба алфавита и оба варианта дополнения:
// ключ приходит из буфера обмена, и требовать от человека помнить, какой
// именно base64 он копировал, — лишний способ получить отказ на ровном месте.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("пусто")
	}
	for _, e := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("не base64")
}

func encodeKey(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
