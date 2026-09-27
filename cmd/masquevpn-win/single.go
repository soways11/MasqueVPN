//go:build windows

package main

// Один экземпляр программы на систему.
//
// # Зачем
//
// С тех пор как закрытие окна прячет программу в значок, а не завершает её,
// второй запуск перестал быть безобидным. Первая копия держит адаптер
// Wintun и настройки сети; вторая показывает кнопку «Подключиться», которая
// ничего не может сделать — адаптер занят. Человек видит рабочее с виду
// окно, которое не работает, и причина ниоткуда не следует.
//
// Поэтому второй запуск не поднимает второе окно, а выводит на экран уже
// работающее и завершается. Это же поведение у всего, что живёт в области
// уведомлений: повторный щелчок по значку программы показывает её, а не
// запускает заново.
//
// # Как
//
// Двумя способами сразу, и оба нужны.
//
// Окно ищется по имени класса — это работает до запроса UAC и потому не
// показывает лишнего окна с правами администратора: нашли чужое окно,
// показали его, вышли.
//
// Мьютекс проверяется уже после повышения прав и ловит случай, когда окно
// ещё не создано: две копии, запущенные одновременно, успели бы проскочить
// проверку по окну обе.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// singleMutexName — имя мьютекса. Local\, а не Global\: экземпляр
// ограничивается сеансом пользователя, а не всей машиной, — в терминальной
// сессии у каждого свой клиент и свой адаптер.
const singleMutexName = `Local\masquevpn-single-instance`

// showMessageName — сообщение «покажись», которое вторая копия посылает
// первой. Зарегистрированное, а не WM_APP+N: номер в этом диапазоне мог бы
// совпасть с чужим, а зарегистрированное уникально в системе.
const showMessageName = "masquevpn.show-window"

var (
	singleMutex windows.Handle
	showMessage uint32
)

// activateRunning ищет уже работающую копию и выводит её окно на экран.
// Возвращает true, если копия нашлась и этой программе делать нечего.
func activateRunning() bool {
	hwnd := findOurWindow()
	if hwnd == 0 {
		return false
	}
	procPostMessage.Call(uintptr(hwnd), uintptr(showMessageID()), 0, 0)
	return true
}

func findOurWindow() windows.HWND {
	h, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(utf16(windowClass))), 0)
	return windows.HWND(h)
}

// showMessageID регистрирует (или находит) номер сообщения «покажись».
func showMessageID() uint32 {
	if showMessage == 0 {
		r, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(utf16(showMessageName))))
		showMessage = uint32(r)
	}
	return showMessage
}

// claimSingleInstance занимает мьютекс. Возвращает false, если копия уже
// работает, — тогда программе следует завершиться.
//
// Мьютекс намеренно не освобождается: он живёт до конца процесса и
// освобождается системой. Освобождать его в defer значило бы открыть окно
// для второй копии на время завершения первой.
func claimSingleInstance() bool {
	name, err := windows.UTF16PtrFromString(singleMutexName)
	if err != nil {
		return true // не смогли проверить — пусть работает
	}
	h, err := windows.CreateMutex(nil, false, name)
	if h != 0 {
		singleMutex = h
	}
	return err != windows.ERROR_ALREADY_EXISTS
}
