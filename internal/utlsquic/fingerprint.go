//go:build utls

package utlsquic

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"time"

	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// Снятый отпечаток браузера: хранение и восстановление.
//
// # Зачем
//
// Встроенные профили uquic заканчиваются на Chrome 115 (2023 год) и новых не
// появится: у uquic нет версий выше v0.0.6. Из свежих спеков uTLS профиль не
// собрать — там нет транспортных параметров QUIC (см. комментарий в utlsquic.go).
//
// Остаётся один честный путь: снять отпечаток с настоящего браузера. В первом
// Initial-пакете есть всё необходимое, и оно воспроизводится побайтово. Профиль
// хранится в JSON, подставляется через Config.CustomSpec — без перекомпиляции.
// Обновление отпечатка превращается в перезапуск одной команды.

// Fingerprint — снятый с браузера QUIC-отпечаток в переносимом виде.
type Fingerprint struct {
	// Source — откуда снят, свободным текстом (например "Chrome 141, linux").
	Source string `json:"source"`
	// CapturedAt — когда снят.
	CapturedAt string `json:"captured_at"`

	// DatagramSize — размер первой UDP-датаграммы (браузеры добивают её паддингом).
	DatagramSize int `json:"datagram_size"`
	// SrcConnIDLen / DestConnIDLen — длины Connection ID в открытом заголовке.
	SrcConnIDLen  int `json:"src_conn_id_len"`
	DestConnIDLen int `json:"dest_conn_id_len"`
	// PacketNumberLen / InitPacketNumber — номер первого пакета и его длина.
	// Chrome, например, начинает нумерацию с 1, а не с 0 — это тоже часть отпечатка.
	PacketNumberLen  int    `json:"packet_number_len"`
	InitPacketNumber uint64 `json:"init_packet_number"`

	// CipherSuites — шифронаборы в порядке отправки.
	CipherSuites []uint16 `json:"cipher_suites"`
	// Extensions — расширения TLS в порядке отправки, с сырыми данными.
	Extensions []Extension `json:"extensions"`
	// TransportParams — транспортные параметры QUIC в порядке отправки.
	TransportParams []TransportParam `json:"transport_params"`
}

// Extension — одно расширение ClientHello: номер и сырые байты значения.
type Extension struct {
	ID   uint16 `json:"id"`
	Data []byte `json:"data,omitempty"`
}

// TransportParam — один транспортный параметр QUIC.
type TransportParam struct {
	ID    uint64 `json:"id"`
	Value []byte `json:"value,omitempty"`
}

// SaveFingerprint записывает отпечаток в файл.
func SaveFingerprint(path string, fp *Fingerprint) error {
	b, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// LoadFingerprint читает отпечаток из файла.
func LoadFingerprint(path string) (*Fingerprint, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fp Fingerprint
	if err := json.Unmarshal(b, &fp); err != nil {
		return nil, fmt.Errorf("utlsquic: разбор отпечатка %s: %w", path, err)
	}
	if len(fp.Extensions) == 0 {
		return nil, fmt.Errorf("utlsquic: в отпечатке %s нет расширений", path)
	}
	return &fp, nil
}

// Spec собирает из отпечатка профиль для uquic, пригодный для Config.CustomSpec.
//
// Расширения, которые обязаны быть живыми (SNI, key_share, транспортные
// параметры и прочие), восстанавливаются типизированными — иначе рукопожатие не
// состоится. Остальные переносятся байт в байт как GenericExtension: так
// сохраняются и те, чьей структуры мы не знаем (GREASE и будущие).
// Исключение — ECH: он выбрасывается, см. Spec.
func (fp *Fingerprint) Spec() (*uquic.QUICSpec, error) {
	exts := make([]utls.TLSExtension, 0, len(fp.Extensions))
	var hasTP bool
	for _, e := range fp.Extensions {
		if e.ID == extECH {
			// ECH из отпечатка ВЫБРАСЫВАЕТСЯ, даже если браузер его шлёт.
			// Российский DPI режет соединения с encrypted_client_hello сразу,
			// по самому факту наличия расширения, — то есть точное повторение
			// браузера здесь означало бы не пройти вовсе. Проекту ECH и не
			// нужен: SNI открыт по решению от 2026-09-17, скрывать нечего.
			//
			// Отпечаток от этого отличается от снятого на одно расширение.
			// Размен осознанный: «Chrome с выключенным ECH» — живое сочетание
			// (ECH отключается флагом и групповой политикой), а вот соединение,
			// которое режут на рукопожатии, не спасёт никакая точность.
			continue
		}
		ext, isTP, err := buildExtension(e, fp.TransportParams)
		if err != nil {
			return nil, err
		}
		if isTP {
			hasTP = true
		}
		exts = append(exts, ext)
	}
	if !hasTP {
		return nil, fmt.Errorf("utlsquic: в отпечатке нет quic_transport_parameters (57) — uquic такой профиль не примет")
	}

	dgram := fp.DatagramSize
	if dgram <= 0 {
		dgram = uquic.DefaultUDPDatagramMinSize
	}
	pnLen := fp.PacketNumberLen
	if pnLen <= 0 {
		pnLen = 1
	}
	return &uquic.QUICSpec{
		InitialPacketSpec: uquic.InitialPacketSpec{
			SrcConnIDLength:        fp.SrcConnIDLen,
			DestConnIDLength:       fp.DestConnIDLen,
			InitPacketNumberLength: uquic.PacketNumberLen(pnLen),
			InitPacketNumber:       fp.InitPacketNumber,
			ClientTokenLength:      0,
			// Разброс числа PING/CRYPTO/PADDING-фреймов из одной записи не
			// восстановить: браузер выбирает его случайно на каждое соединение.
			// Берём диапазоны, наблюдаемые у Chrome, а длину полезной нагрузки
			// считаем из размера датаграммы — она-то в записи есть.
			FrameBuilder: &uquic.QUICRandomFrames{
				MinPING:    0,
				MaxPING:    maxPINGFrames,
				MinCRYPTO:  1,
				MaxCRYPTO:  maxCRYPTOFrames,
				MinPADDING: 3,
				MaxPADDING: 6,
				Length:     uint16(payloadLength(dgram, fp.DestConnIDLen, fp.SrcConnIDLen, pnLen)),
			},
			// Место, которое займут заголовки этих кадров сверх исходного
			// единственного CRYPTO-кадра. Без запаса криптоданных набирается
			// ровно «под завязку», перекладывание в свои кадры пакет
			// раздувает, и добивать PADDING уже нечем: размер первого
			// Initial-пакета начинает плавать вместо постоянного.
			FrameOverheadReserve: maxCRYPTOFrames*cryptoFrameHeaderMax + maxPINGFrames,
		},
		ClientHelloSpec: &utls.ClientHelloSpec{
			CipherSuites:       fp.CipherSuites,
			CompressionMethods: []byte{0},
			Extensions:         exts,
			TLSVersMin:         utls.VersionTLS13,
			TLSVersMax:         utls.VersionTLS13,
		},
		UDPDatagramMinSize: dgram,
	}, nil
}

// Пределы разброса кадров в первом Initial-пакете и цена их заголовков.
const (
	maxPINGFrames   = 10
	maxCRYPTOFrames = 10
	// Заголовок CRYPTO-кадра: тип (1 байт) + смещение и длина варинтами
	// (до 4 байт каждый).
	cryptoFrameHeaderMax = 9
)

// Номера расширений, которые нужно восстанавливать типизированными.
const (
	extSNI                = 0
	extSupportedGroups    = 10
	extSigAlgs            = 13
	extALPN               = 16
	extCompressCert       = 27
	extSupportedVersions  = 43
	extPSKModes           = 45
	extKeyShare           = 51
	extQUICTransportParam = 57
	extALPS               = 17513
	extALPSNew            = 17613
	extECH                = 0xfe0d
)

func buildExtension(e Extension, tps []TransportParam) (utls.TLSExtension, bool, error) {
	switch e.ID {
	case extSNI:
		// Имя подставляется из конфигурации на этапе подключения.
		return &utls.SNIExtension{}, false, nil

	case extSupportedGroups:
		groups, err := parseUint16List(e.Data)
		if err != nil {
			return nil, false, fmt.Errorf("supported_groups: %w", err)
		}
		curves := make([]utls.CurveID, len(groups))
		for i, g := range groups {
			curves[i] = utls.CurveID(g)
		}
		return &utls.SupportedCurvesExtension{Curves: curves}, false, nil

	case extSigAlgs:
		algs, err := parseUint16List(e.Data)
		if err != nil {
			return nil, false, fmt.Errorf("signature_algorithms: %w", err)
		}
		schemes := make([]utls.SignatureScheme, len(algs))
		for i, a := range algs {
			schemes[i] = utls.SignatureScheme(a)
		}
		return &utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: schemes}, false, nil

	case extALPN:
		protos, err := parseALPN(e.Data)
		if err != nil {
			return nil, false, err
		}
		return &utls.ALPNExtension{AlpnProtocols: protos}, false, nil

	case extCompressCert:
		algs, err := parseUint16ListShort(e.Data)
		if err != nil {
			return nil, false, fmt.Errorf("compress_certificate: %w", err)
		}
		out := make([]utls.CertCompressionAlgo, len(algs))
		for i, a := range algs {
			out[i] = utls.CertCompressionAlgo(a)
		}
		return &utls.UtlsCompressCertExtension{Algorithms: out}, false, nil

	case extSupportedVersions:
		vers, err := parseUint16ListShort(e.Data)
		if err != nil {
			return nil, false, fmt.Errorf("supported_versions: %w", err)
		}
		return &utls.SupportedVersionsExtension{Versions: vers}, false, nil

	case extPSKModes:
		if len(e.Data) < 1 {
			return nil, false, fmt.Errorf("psk_key_exchange_modes: пусто")
		}
		n := int(e.Data[0])
		if 1+n > len(e.Data) {
			return nil, false, fmt.Errorf("psk_key_exchange_modes: обрыв")
		}
		return &utls.PSKKeyExchangeModesExtension{Modes: append([]byte(nil), e.Data[1:1+n]...)}, false, nil

	case extKeyShare:
		shares, err := parseKeyShareGroups(e.Data)
		if err != nil {
			return nil, false, err
		}
		return &utls.KeyShareExtension{KeyShares: shares}, false, nil

	case extQUICTransportParam:
		return &utls.QUICTransportParametersExtension{
			TransportParameters: buildTransportParams(tps),
		}, true, nil

	case extALPS, extALPSNew:
		protos, err := parseALPN(e.Data)
		if err != nil {
			return nil, false, fmt.Errorf("application_settings: %w", err)
		}
		// У ALPS два номера: старый 17513 и новый 17613. Браузеры переходят на
		// новый (Chrome 153 шлёт именно его), и номер обязан сохраниться —
		// иначе отпечаток отличается от снятого одним полем, которое читается
		// прямо из ClientHello.
		if e.ID == extALPSNew {
			return &utls.ApplicationSettingsExtensionNew{SupportedProtocols: protos}, false, nil
		}
		return &utls.ApplicationSettingsExtension{SupportedProtocols: protos}, false, nil

	default:
		// Структура неизвестна — переносим байт в байт.
		return &utls.GenericExtension{Id: e.ID, Data: append([]byte(nil), e.Data...)}, false, nil
	}
}

// parseKeyShareGroups достаёт только идентификаторы групп: сами ключи uTLS
// сгенерирует заново, переносить чужой открытый ключ нельзя.
//
// Исключение — GREASE-группа: для неё ключа не существует, и BoringSSL шлёт
// один нулевой байт. Если оставить тело пустым, uTLS отправит GREASE-группу
// с нулевой длиной key_exchange, сервер уйдёт в HelloRetryRequest, и
// рукопожатие развалится с «tls: unexpected message». Проявилось это только
// когда в профиле появился GREASE, но сломано было с самого начала: у
// НАСТОЯЩЕГО Chrome GREASE в key_share есть всегда, то есть перенос снятого
// с браузера отпечатка не сработал бы.
func parseKeyShareGroups(b []byte) ([]utls.KeyShare, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("key_share: пусто")
	}
	total := int(binary.BigEndian.Uint16(b[:2]))
	if 2+total > len(b) {
		return nil, fmt.Errorf("key_share: обрыв")
	}
	var out []utls.KeyShare
	p := b[2 : 2+total]
	for len(p) >= 4 {
		group := binary.BigEndian.Uint16(p[:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+l > len(p) {
			return nil, fmt.Errorf("key_share: обрыв записи группы")
		}
		if isGREASE(group) {
			out = append(out, utls.KeyShare{Group: utls.CurveID(group), Data: []byte{0}})
		} else {
			out = append(out, utls.KeyShare{Group: utls.CurveID(group)})
		}
		p = p[4+l:]
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("key_share: не найдено ни одной группы")
	}
	return out, nil
}

func parseUint16List(b []byte) ([]uint16, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("обрыв длины")
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if 2+n > len(b) || n%2 != 0 {
		return nil, fmt.Errorf("обрыв списка")
	}
	out := make([]uint16, 0, n/2)
	for i := 2; i < 2+n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:i+2]))
	}
	return out, nil
}

// parseUint16ListShort — список с однобайтовой длиной (в байтах).
func parseUint16ListShort(b []byte) ([]uint16, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("обрыв длины")
	}
	n := int(b[0])
	if 1+n > len(b) || n%2 != 0 {
		return nil, fmt.Errorf("обрыв списка")
	}
	out := make([]uint16, 0, n/2)
	for i := 1; i < 1+n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:i+2]))
	}
	return out, nil
}

func parseALPN(b []byte) ([]string, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("alpn: обрыв длины")
	}
	total := int(binary.BigEndian.Uint16(b[:2]))
	if 2+total > len(b) {
		return nil, fmt.Errorf("alpn: обрыв")
	}
	var out []string
	p := b[2 : 2+total]
	for len(p) > 0 {
		l := int(p[0])
		if 1+l > len(p) {
			return nil, fmt.Errorf("alpn: обрыв записи")
		}
		out = append(out, string(p[1:1+l]))
		p = p[1+l:]
	}
	return out, nil
}

func nowStamp() string { return time.Now().UTC().Format(time.RFC3339) }

// Идентификаторы транспортных параметров, которые uquic разбирает по типу.
// Для них нужен именно типизированный объект: PopulateFromUQUIC делает
// приведение типа и на универсальном параметре впадает в панику.
const (
	tpMaxIdleTimeout              = 0x01
	tpInitialMaxData              = 0x04
	tpInitialMaxStreamDataBidiLoc = 0x05
	tpInitialMaxStreamDataBidiRem = 0x06
	tpInitialMaxStreamDataUni     = 0x07
	tpInitialMaxStreamsBidi       = 0x08
	tpInitialMaxStreamsUni        = 0x09
	tpMaxAckDelay                 = 0x0b
	tpDisableActiveMigration      = 0x0c
	tpActiveConnectionIDLimit     = 0x0e
	tpInitialSourceConnectionID   = 0x0f
	tpMaxDatagramFrameSize        = 0x20
)

// buildTransportParams восстанавливает список транспортных параметров из записи.
//
// Порядок сохраняется: он часть отпечатка. Значения известных параметров
// разворачиваются в типизированные объекты, остальные (GREASE, version_information,
// ack_delay_exponent и прочие, которых uquic не разбирает) переносятся как есть —
// uquic их игнорирует при разборе, но отправляет в сеть байт в байт.
func buildTransportParams(tps []TransportParam) utls.TransportParameters {
	out := make(utls.TransportParameters, 0, len(tps))
	for _, p := range tps {
		v, _ := readVarint(p.Value) // для параметров-чисел значение — варинт
		switch p.ID {
		case tpMaxIdleTimeout:
			out = append(out, utls.MaxIdleTimeout(v))
		case tpInitialMaxData:
			out = append(out, utls.InitialMaxData(v))
		case tpInitialMaxStreamDataBidiLoc:
			out = append(out, utls.InitialMaxStreamDataBidiLocal(v))
		case tpInitialMaxStreamDataBidiRem:
			out = append(out, utls.InitialMaxStreamDataBidiRemote(v))
		case tpInitialMaxStreamDataUni:
			out = append(out, utls.InitialMaxStreamDataUni(v))
		case tpInitialMaxStreamsBidi:
			out = append(out, utls.InitialMaxStreamsBidi(v))
		case tpInitialMaxStreamsUni:
			out = append(out, utls.InitialMaxStreamsUni(v))
		case tpMaxAckDelay:
			out = append(out, utls.MaxAckDelay(v))
		case tpDisableActiveMigration:
			out = append(out, &utls.DisableActiveMigration{})
		case tpActiveConnectionIDLimit:
			out = append(out, utls.ActiveConnectionIDLimit(v))
		case tpInitialSourceConnectionID:
			// Пустой — чтобы uquic подставил СВОЙ идентификатор соединения.
			// Переносить чужой из записи нельзя: соединение будет нерабочим.
			out = append(out, utls.InitialSourceConnectionID{})
		case tpMaxDatagramFrameSize:
			out = append(out, utls.MaxDatagramFrameSize(v))
		default:
			out = append(out, &utls.FakeQUICTransportParameter{
				Id:  p.ID,
				Val: append([]byte(nil), p.Value...),
			})
		}
	}
	return out
}

// payloadLength считает длину полезной нагрузки Initial-пакета по наблюдаемому
// размеру датаграммы: вычитаем открытый заголовок и место под тег аутентичности.
//
//	1 (первый байт) + 4 (версия) + 1 + DCID + 1 + SCID + 1 (длина токена)
//	+ 2 (поле длины) + длина номера пакета + 16 (тег)
func payloadLength(datagram, dcid, scid, pnLen int) int {
	overhead := 1 + 4 + 1 + dcid + 1 + scid + 1 + 2 + pnLen + 16
	n := datagram - overhead
	if n < 1 {
		n = 1
	}
	return n
}

// LoadSpec читает снятый отпечаток (JSON от fpcapture) и возвращает его в
// виде, пригодном для Config.CustomSpec.
//
// Возвращается САМА ЗАПИСЬ, а не готовый профиль: профиль одноразовый и
// собирается заново на каждый дозвон (см. resolveSpec). Здесь же он строится
// один раз — чтобы негодная запись отвергалась сразу при чтении
// конфигурации, а не через сутки при первой ротации.
func LoadSpec(path string) (any, error) {
	fp, err := LoadFingerprint(path)
	if err != nil {
		return nil, err
	}
	if _, err := fp.Spec(); err != nil {
		return nil, err
	}
	return fp, nil
}
