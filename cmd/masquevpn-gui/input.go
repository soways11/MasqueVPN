//go:build linux

package main

// Ввод с клавиатуры и буфер обмена.
//
// # Почему поля ввода здесь свои
//
// В Windows поле ввода — настоящий системный элемент: курсор, выделение,
// Ctrl+V и экранная клавиатура достаются даром. В X11 ничего подобного нет:
// протокол даёт коды клавиш и владение выделением, а всё остальное пишет
// приложение. Поэтому здесь минимальное поле: курсор в конце строки, ввод
// символов, Backspace, переход по Tab и вставка по Ctrl+V.
//
// Это сознательно меньше, чем в Windows: нет выделения мышью, нет
// перемещения курсора стрелками. Поля заполняют вставкой из буфера или
// набирают один раз, и полноценный редактор здесь не окупается — а вот
// вставка окупается сразу, ссылка в 170 знаков руками не набирается.

import (
	"strings"
	"unicode"

	"github.com/jezek/xgb/xproto"

	"github.com/soways11/masquevpn/internal/config"
	"github.com/soways11/masquevpn/internal/gui"
	"github.com/soways11/masquevpn/internal/guiraster"
)

// Коды клавиш, которые нужны по имени.
const (
	keyBackspace = 0xff08
	keyTab       = 0xff09
	keyReturn    = 0xff0d
	keyEscape    = 0xff1b
	keyDelete    = 0xffff
)

// onKey разбирает нажатие клавиши.
func (a *app) onKey(e xproto.KeyPressEvent) {
	if a.menu != nil {
		a.closeMenu()
		a.invalidate()
		return
	}
	sym := a.keysym(e.Detail, e.State)
	ctrl := e.State&xproto.ModMaskControl != 0

	if a.screen != gui.ScreenAdd {
		if sym == keyEscape {
			a.activate(gui.ItemBack)
		}
		return
	}

	switch {
	case ctrl && (sym == 'v' || sym == 'V' || sym == 'м' || sym == 'М'):
		// И латинская, и кириллическая раскладка: человек не обязан
		// переключаться ради вставки.
		a.requestPaste()
	case sym == keyEscape:
		a.activate(gui.ItemBack)
	case sym == keyReturn:
		a.confirmAdd()
	case sym == keyTab:
		a.focus = (a.focus + 1) % gui.MaxAddFields
		a.invalidate()
	case sym == keyBackspace || sym == keyDelete:
		if s := a.fields[a.focus]; s != "" {
			r := []rune(s)
			a.fields[a.focus] = string(r[:len(r)-1])
			a.clearNotice()
			a.invalidate()
		}
	default:
		if r := runeOf(sym); r != 0 {
			a.fields[a.focus] += string(r)
			a.clearNotice()
			a.invalidate()
		}
	}
}

// keysym переводит код клавиши в символ с учётом модификаторов.
//
// Карта запрашивается один раз и кешируется: она меняется только при смене
// раскладки, а такое событие мы всё равно не обрабатываем.
func (a *app) keysym(code xproto.Keycode, state uint16) uint32 {
	if a.keymap == nil {
		a.loadKeymap()
	}
	per := int(a.keysPerCode)
	idx := int(code) - int(a.firstKeycode)
	if a.keymap == nil || per == 0 || idx < 0 || (idx+1)*per > len(a.keymap) {
		return 0
	}
	shift := state&xproto.ModMaskShift != 0
	// Вторая колонка карты — символ с Shift. Больше уровней (раскладки,
	// AltGr) не разбираем: адрес, ключ и имя профиля набираются в первых
	// двух.
	col := 0
	if shift && per > 1 {
		col = 1
	}
	return uint32(a.keymap[idx*per+col])
}

func (a *app) loadKeymap() {
	setup := xproto.Setup(a.win.conn)
	first := setup.MinKeycode
	count := byte(setup.MaxKeycode - setup.MinKeycode + 1)
	reply, err := xproto.GetKeyboardMapping(a.win.conn, first, count).Reply()
	if err != nil {
		return
	}
	a.keymap = reply.Keysyms
	a.keysPerCode = reply.KeysymsPerKeycode
	a.firstKeycode = first
}

// runeOf переводит keysym в символ.
//
// Латиница и знаки лежат в кодах, совпадающих с ASCII. Кириллица — в
// диапазоне 0x6a0…0x6ff, и порядок там не алфавитный, а по KOI8-R: это
// наследие, которое приходится разворачивать таблицей.
func runeOf(sym uint32) rune {
	switch {
	case sym == 0:
		return 0
	case sym >= 0x20 && sym <= 0x7e:
		return rune(sym)
	case sym >= 0x6a0 && sym <= 0x6ff:
		if r, ok := cyrillicKeysyms[sym]; ok {
			return r
		}
	}
	return 0
}

// cyrillicKeysyms — раскладка кириллицы X11 (KOI8-R порядок).
var cyrillicKeysyms = map[uint32]rune{
	0x6a1: 'ё', 0x6b1: 'Ё',
	0x6c0: 'ю', 0x6c1: 'а', 0x6c2: 'б', 0x6c3: 'ц', 0x6c4: 'д', 0x6c5: 'е',
	0x6c6: 'ф', 0x6c7: 'г', 0x6c8: 'х', 0x6c9: 'и', 0x6ca: 'й', 0x6cb: 'к',
	0x6cc: 'л', 0x6cd: 'м', 0x6ce: 'н', 0x6cf: 'о',
	0x6d0: 'п', 0x6d1: 'я', 0x6d2: 'р', 0x6d3: 'с', 0x6d4: 'т', 0x6d5: 'у',
	0x6d6: 'ж', 0x6d7: 'в', 0x6d8: 'ь', 0x6d9: 'ы', 0x6da: 'з', 0x6db: 'ш',
	0x6dc: 'э', 0x6dd: 'щ', 0x6de: 'ч', 0x6df: 'ъ',
	0x6e0: 'Ю', 0x6e1: 'А', 0x6e2: 'Б', 0x6e3: 'Ц', 0x6e4: 'Д', 0x6e5: 'Е',
	0x6e6: 'Ф', 0x6e7: 'Г', 0x6e8: 'Х', 0x6e9: 'И', 0x6ea: 'Й', 0x6eb: 'К',
	0x6ec: 'Л', 0x6ed: 'М', 0x6ee: 'Н', 0x6ef: 'О',
	0x6f0: 'П', 0x6f1: 'Я', 0x6f2: 'Р', 0x6f3: 'С', 0x6f4: 'Т', 0x6f5: 'У',
	0x6f6: 'Ж', 0x6f7: 'В', 0x6f8: 'Ь', 0x6f9: 'Ы', 0x6fa: 'З', 0x6fb: 'Ш',
	0x6fc: 'Э', 0x6fd: 'Щ', 0x6fe: 'Ч', 0x6ff: 'Ъ',
}

// ---------- буфер обмена ----------

// requestPaste просит владельца буфера отдать текст.
//
// В X11 буфера обмена как хранилища нет: есть владелец выделения, который
// отдаёт данные по запросу. Поэтому вставка асинхронна — ответ придёт
// событием SelectionNotify.
func (a *app) requestPaste() {
	xproto.ConvertSelection(a.win.conn, a.win.id, a.win.atoms.clipboard,
		a.win.atoms.utf8String, a.win.atoms.xselData, xproto.TimeCurrentTime)
}

// onPaste принимает ответ владельца буфера.
func (a *app) onPaste(e xproto.SelectionNotifyEvent) {
	if e.Property == 0 {
		a.fail(0, "В буфере обмена пусто или текст недоступен")
		return
	}
	reply, err := xproto.GetProperty(a.win.conn, true, a.win.id, e.Property,
		xproto.GetPropertyTypeAny, 0, 1<<16).Reply()
	if err != nil || reply == nil || len(reply.Value) == 0 {
		a.fail(0, "В буфере обмена пусто")
		return
	}
	text := strings.TrimSpace(string(reply.Value))
	if text == "" {
		a.fail(0, "В буфере обмена пусто")
		return
	}

	// Ссылку или конфигурацию раскладываем по полям — так видно, к какому
	// серверу подключишься. Остальное кладём в поле под курсором.
	if cfg, name, err := config.ParseShared(text); err == nil {
		a.fields[gui.FieldServer] = cfg.Server
		a.fields[gui.FieldAuthKey] = string(cfg.AuthKey)
		a.fields[gui.FieldClientID] = cfg.ClientID
		if name != "" {
			a.fields[gui.FieldName] = name
		}
		a.clearNotice()
		a.notice = "Значения из буфера — проверьте адрес сервера и нажмите «Добавить»."
		a.focus = gui.FieldServer
	} else {
		a.fields[a.focus] += strings.TrimSpace(strings.SplitN(text, "\n", 2)[0])
		a.clearNotice()
	}
	a.invalidate()
}

// offerClipboard объявляет себя владельцем буфера обмена.
//
// Отдать текст «в систему» и забыть, как в Windows, нельзя: пока программа
// жива, она обязана отвечать на запросы владельца. Поэтому текст хранится
// здесь и выдаётся по запросу в цикле событий.
func (a *app) offerClipboard(text string) {
	a.clipboard = text
	xproto.SetSelectionOwner(a.win.conn, a.win.id, a.win.atoms.clipboard, xproto.TimeCurrentTime)
}

// onSelectionRequest отдаёт текст тому, кто его попросил.
func (a *app) onSelectionRequest(e xproto.SelectionRequestEvent) {
	prop := e.Property
	if prop == 0 {
		prop = e.Target // старое соглашение, до ICCCM
	}
	switch e.Target {
	case a.win.atoms.targets:
		data := make([]byte, 8)
		putAtom(data[0:], a.win.atoms.targets)
		putAtom(data[4:], a.win.atoms.utf8String)
		xproto.ChangeProperty(a.win.conn, xproto.PropModeReplace, e.Requestor, prop,
			xproto.AtomAtom, 32, 2, data)
	case a.win.atoms.utf8String, xproto.AtomString:
		xproto.ChangeProperty(a.win.conn, xproto.PropModeReplace, e.Requestor, prop,
			e.Target, 8, uint32(len(a.clipboard)), []byte(a.clipboard))
	default:
		prop = 0 // не умеем отдавать в этом виде
	}

	ev := xproto.SelectionNotifyEvent{
		Time:      e.Time,
		Requestor: e.Requestor,
		Selection: e.Selection,
		Target:    e.Target,
		Property:  prop,
	}
	xproto.SendEvent(a.win.conn, false, e.Requestor, 0, string(ev.Bytes()))
}

func putAtom(buf []byte, a xproto.Atom) {
	v := uint32(a)
	buf[0] = byte(v)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
}

// ---------- отрисовка содержимого полей ----------

// paintFields дорисовывает то, чего нет в общей отрисовке: текст внутри
// полей ввода и курсор. В Windows это делает системный элемент, здесь —
// мы сами.
func (a *app) paintFields(cv *guiraster.Canvas, blink bool) {
	if a.screen != gui.ScreenAdd {
		return
	}
	l := gui.AddLayout(a.editing, a.winH)
	for i, f := range l.Fields {
		box := l.Edit(f.Box)
		text := a.fields[i]

		// Поле в фокусе обведено акцентом: без этого непонятно, куда
		// попадут набранные буквы.
		if i == a.focus {
			cv.Border(f.Box, gui.RadiusSm, gui.ColorAccentDim, 1)
		}

		if text == "" {
			if i == a.focus && blink {
				cv.Fill(gui.Rect{X: box.X, Y: box.Y + 4, W: 1, H: box.H - 8}, gui.ColorText)
			}
			cv.Text(fieldHint(i), gui.FaceSmall, box, gui.ColorMuted, gui.AlignLeft)
			continue
		}

		// Длинный текст показываем хвостом: при наборе важно видеть то, что
		// набирается, а не начало строки.
		shown := text
		for cv.Width(shown, gui.FaceRow) > float64(box.W-10) && len([]rune(shown)) > 1 {
			r := []rune(shown)
			shown = string(r[1:])
		}
		cv.Text(shown, gui.FaceRow, box, gui.ColorText, gui.AlignLeft)

		if i == a.focus && blink {
			x := box.X + int32(cv.Width(shown, gui.FaceRow)+1.5)
			if x > box.Right()-2 {
				x = box.Right() - 2
			}
			cv.Fill(gui.Rect{X: x, Y: box.Y + 4, W: 1, H: box.H - 8}, gui.ColorText)
		}
	}
}

// fieldHint — подсказка в пустом поле, как cue banner в Windows.
func fieldHint(i int) string {
	switch i {
	case gui.FieldServer:
		return "vpn.example.com:443"
	case gui.FieldAuthKey:
		return "ключ из clients add"
	case gui.FieldClientID:
		return "66bbb6180401ba34"
	default:
		return "необязательно — иначе домен сервера"
	}
}

// visibleRunes — сколько знаков строки влезает в ширину. Вынесено, чтобы
// не считать это в цикле отрисовки дважды.
func visibleRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}

// isPrintable — годится ли символ для поля ввода.
func isPrintable(r rune) bool {
	return r != 0 && (unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsPunct(r) ||
		unicode.IsSymbol(r) || r == ' ')
}
