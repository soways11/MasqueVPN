// Package tunnel соединяет TUN-интерфейс с CONNECT-IP сессиями.
//
//   - RunClient — насос клиента: TUN ⇄ одна сессия (masque.Conn или
//     session.Session с ротацией).
//   - Router — маршрутизатор сервера: один TUN ⇄ много сессий, выбор сессии
//     по адресу получателя.
//
// Оба пути обрабатывают *masque.PacketTooLargeError: готовый ICMP
// («Fragmentation Needed» / «Packet Too Big») записывается обратно в TUN, и
// ядро отправителя уменьшает пакеты. Без этого крупные пакеты пропадали бы
// молча — «чёрная дыра MTU», при которой TCP-соединение устанавливается и
// виснет на первой же большой передаче.
//
// Пакет не зависит от ОС: устройство — любой tun.Device, в том числе
// дескриптор, полученный от Android VpnService.
package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/soways11/masquevpn/internal/masque"
	"github.com/soways11/masquevpn/internal/tun"
)

// PacketConn — источник и приёмник IP-пакетов туннеля
// (*masque.Conn, *session.Session).
type PacketConn interface {
	ReadPacket(b []byte) (int, error)
	WritePacket(pkt []byte) error
}

// Counters — счётчики насоса.
type Counters struct {
	ToTunnel   atomic.Uint64 // пакетов из TUN отправлено в туннель
	FromTunnel atomic.Uint64 // пакетов из туннеля записано в TUN
	ICMP       atomic.Uint64 // ICMP «слишком большой» записано в TUN
	Rejected   atomic.Uint64 // отвергнуто политикой адресов сессии
	NoRoute    atomic.Uint64 // сервер: нет сессии для адреса получателя
	Overflow   atomic.Uint64 // сервер: очередь сессии переполнена
}

const maxPacket = 65535

// ClientOptions — необязательные параметры RunClient.
type ClientOptions struct {
	Logger   *slog.Logger
	Counters *Counters
}

// handleWriteErr обрабатывает ошибку отправки пакета в туннель.
// Возвращает ошибку только если продолжать нельзя.
func handleWriteErr(err error, dev tun.Device, cnt *Counters, log *slog.Logger) error {
	if tl, ok := masque.AsPacketTooLarge(err); ok {
		if tl.ICMP != nil {
			if _, werr := dev.Write(tl.ICMP); werr == nil {
				cnt.ICMP.Add(1)
			} else {
				log.Debug("запись ICMP в TUN", "err", werr)
			}
		}
		return nil
	}
	if errors.Is(err, masque.ErrPacketRejected) {
		// Служебный трафик ОС (IPv6 RS/MLD с link-local адреса), пакеты со
		// старым адресом во время смены — не повод рвать туннель.
		cnt.Rejected.Add(1)
		return nil
	}
	return err
}

// RunClient перекачивает пакеты между dev и pc, пока не отменён ctx или
// одна из сторон не вернула ошибку. RunClient владеет dev и pc: при выходе
// закрывает оба (pc — если он io.Closer). Возвращает первую ошибку или nil
// при отмене ctx.
func RunClient(ctx context.Context, dev tun.Device, pc PacketConn, opt ClientOptions) error {
	log := opt.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cnt := opt.Counters
	if cnt == nil {
		cnt = new(Counters)
	}

	ctx, cancel := context.WithCancelCause(ctx)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() { // TUN → туннель
		defer wg.Done()
		buf := make([]byte, maxPacket)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				cancel(err)
				return
			}
			if n == 0 {
				continue
			}
			if err := pc.WritePacket(buf[:n]); err != nil {
				if err := handleWriteErr(err, dev, cnt, log); err != nil {
					cancel(err)
					return
				}
				continue
			}
			cnt.ToTunnel.Add(1)
		}
	}()

	go func() { // туннель → TUN
		defer wg.Done()
		buf := make([]byte, maxPacket)
		for {
			n, err := pc.ReadPacket(buf)
			if err != nil {
				cancel(err)
				return
			}
			if _, err := dev.Write(buf[:n]); err != nil {
				cancel(err)
				return
			}
			cnt.FromTunnel.Add(1)
		}
	}()

	<-ctx.Done()
	_ = dev.Close()
	if c, ok := pc.(io.Closer); ok {
		_ = c.Close()
	}
	wg.Wait()
	err := context.Cause(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// dstAddr извлекает адрес получателя из IP-пакета.
func dstAddr(p []byte) (netip.Addr, bool) {
	if len(p) < 1 {
		return netip.Addr{}, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(p[16:20])), true
	case 6:
		if len(p) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(p[24:40])), true
	}
	return netip.Addr{}, false
}
