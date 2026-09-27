package masque

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Сообщения об MTU для отправителя внутри туннеля.
//
// # Проблема, которую это решает
//
// Если IP-пакет не помещается в QUIC-датаграмму, отправить его нельзя. Раньше мы
// просто возвращали ошибку вызывающему — и на этом всё. Отправитель ВНУТРИ
// туннеля об этом не узнавал: для него пакет просто исчезал.
//
// Для TCP это худший из возможных исходов. Мелкие пакеты (рукопожатие) проходят,
// крупные молча пропадают, повторные передачи пропадают тоже — соединение
// устанавливается и виснет на первой же большой передаче. Это классическая
// «чёрная дыра MTU»: симптом выглядит как «интернет работает, но сайты не
// открываются», и ищут его потом очень долго.
//
// Так делает любой маршрутизатор: не можешь переслать из-за размера — верни
// отправителю ICMP, чтобы тот уменьшил пакеты. Мы возвращаем готовый ICMP-пакет
// в ошибке, а слой TUN записывает его обратно в интерфейс.

// PacketTooLargeError — пакет не помещается в датаграмму.
//
// ICMP содержит готовый ответ отправителю (ICMPv4 Fragmentation Needed или
// ICMPv6 Packet Too Big). Его нужно записать обратно в TUN — тогда стек
// отправителя уменьшит размер пакетов сам. Поле может быть nil, если ответ
// построить не удалось.
type PacketTooLargeError struct {
	// MaxSize — сколько байт IP-пакета сейчас помещается в датаграмму.
	MaxSize int
	// ICMP — готовый пакет для отправителя; записать в TUN.
	ICMP []byte
}

func (e *PacketTooLargeError) Error() string {
	return fmt.Sprintf("masque: packet does not fit into a QUIC datagram (max %d bytes)", e.MaxSize)
}

// AsPacketTooLarge извлекает *PacketTooLargeError из ошибки — удобная обёртка
// для слоя TUN, чтобы не тянуть errors.As на каждый вызов.
func AsPacketTooLarge(err error) (*PacketTooLargeError, bool) {
	var e *PacketTooLargeError
	ok := errors.As(err, &e)
	return e, ok
}

const (
	icmpv4DestUnreachable = 3
	icmpv4CodeFragNeeded  = 4
	icmpv6PacketTooBig    = 2
	protoICMPv4           = 1
	protoICMPv6           = 58
)

// buildICMPTooBig строит ICMP-ответ отправителю исходного пакета.
//
// src — адрес, от имени которого приходит сообщение. По умолчанию берётся
// получатель исходного пакета: стеки проверяют вложенную копию пакета, а не
// адрес отправителя ICMP, поэтому для Path MTU Discovery этого достаточно.
// Если известен адрес шлюза туннеля, лучше передать его.
func buildICMPTooBig(orig []byte, mtu int, src netip.Addr) []byte {
	info, err := parsePacket(orig)
	if err != nil {
		return nil
	}
	// Отвечать на ICMP-ошибку ICMP-ошибкой нельзя — получится петля.
	if isICMPError(orig, info) {
		return nil
	}
	if !src.IsValid() {
		src = info.Dst
	}
	if src.Is4() != info.Src.Is4() {
		return nil // семейства не совпадают — корректный ответ не собрать
	}
	if info.Src.Is4() {
		return buildICMPv4FragNeeded(orig, mtu, src, info.Src)
	}
	return buildICMPv6PacketTooBig(orig, mtu, src, info.Src)
}

// isICMPError сообщает, что пакет сам является ICMP-сообщением об ошибке.
func isICMPError(pkt []byte, info packetInfo) bool {
	if info.Src.Is4() {
		if info.Proto != protoICMPv4 || len(pkt) < 21 {
			return false
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+1 {
			return false
		}
		t := pkt[ihl]
		// 0 (echo reply), 8 (echo request) — не ошибки; остальное из низких типов — ошибки.
		return t != 0 && t != 8 && t < 42
	}
	if info.Proto != protoICMPv6 || len(pkt) < 41 {
		return false
	}
	// У ICMPv6 типы ошибок — 0..127.
	return pkt[40] < 128
}

// buildICMPv4FragNeeded — ICMPv4 тип 3 код 4 с указанием MTU следующего перехода
// (RFC 792 плюс RFC 1191). Вкладывается заголовок исходного пакета и 8 байт данных.
func buildICMPv4FragNeeded(orig []byte, mtu int, src, dst netip.Addr) []byte {
	ihl := int(orig[0]&0x0f) * 4
	quote := ihl + 8
	if quote > len(orig) {
		quote = len(orig)
	}

	icmp := make([]byte, 8+quote)
	icmp[0] = icmpv4DestUnreachable
	icmp[1] = icmpv4CodeFragNeeded
	// icmp[2:4] — контрольная сумма, считается ниже
	// icmp[4:6] — не используется
	binary.BigEndian.PutUint16(icmp[6:8], uint16(mtu))
	copy(icmp[8:], orig[:quote])
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))

	pkt := make([]byte, 20+len(icmp))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = protoICMPv4
	s, d := src.As4(), dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))
	copy(pkt[20:], icmp)
	return pkt
}

// buildICMPv6PacketTooBig — ICMPv6 тип 2 (RFC 4443). Вкладывается столько
// исходного пакета, сколько влезает в минимальный MTU IPv6 (1280 байт).
func buildICMPv6PacketTooBig(orig []byte, mtu int, src, dst netip.Addr) []byte {
	const maxTotal = 1280
	quote := len(orig)
	if maxQuote := maxTotal - 40 - 8; quote > maxQuote {
		quote = maxQuote
	}

	icmp := make([]byte, 8+quote)
	icmp[0] = icmpv6PacketTooBig
	icmp[1] = 0
	// icmp[2:4] — контрольная сумма
	binary.BigEndian.PutUint32(icmp[4:8], uint32(mtu))
	copy(icmp[8:], orig[:quote])

	pkt := make([]byte, 40+len(icmp))
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(icmp)))
	pkt[6] = protoICMPv6
	pkt[7] = 64 // hop limit
	s, d := src.As16(), dst.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])

	// Контрольная сумма ICMPv6 считается с псевдозаголовком IPv6.
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(src, dst, icmp))
	copy(pkt[40:], icmp)
	return pkt
}

// checksum — стандартная контрольная сумма в дополнительном коде (RFC 1071).
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// icmpv6Checksum считает сумму по псевдозаголовку IPv6 и телу ICMPv6.
func icmpv6Checksum(src, dst netip.Addr, icmp []byte) uint16 {
	pseudo := make([]byte, 40)
	s, d := src.As16(), dst.As16()
	copy(pseudo[0:16], s[:])
	copy(pseudo[16:32], d[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmp)))
	pseudo[39] = protoICMPv6

	buf := make([]byte, 0, len(pseudo)+len(icmp))
	buf = append(buf, pseudo...)
	buf = append(buf, icmp...)
	return checksum(buf)
}
