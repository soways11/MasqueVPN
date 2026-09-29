package masque

import (
	"net/http"
)

// Ответ на CONNECT, который мы не приняли (защита от простукивания).
//
// Раньше всё нераспознанное уходило в Fallback: «пусть посторонний видит
// сайт». Для GET это правильно, для CONNECT — нет. http.FileServer (и вообще
// почти любой обработчик статики) на метод не смотрит и отдаёт 200 и тело
// страницы. Обычный сервер так не отвечает никогда: CONNECT — не способ
// получить документ. Пробер, отправивший Extended CONNECT с мусорным
// токеном, получал 200 и страницу — признак, по которому нас отличали одним
// запросом.
//
// Теперь на CONNECT отвечаем так, как ответил бы обычный сервер с
// поддержкой WebTransport (а мы объявляем ровно такие SETTINGS):
//
//   - CONNECT без :protocol — 405: мы origin-сервер, а не прокси;
//   - :protocol, которого мы не принимаем, — 501 (RFC 8441, §5.1);
//   - неизвестный маршрут — 404;
//   - наш маршрут, но проверка не прошла — тот же 404, байт в байт.
//
// Последнее важнее всего: по ответу нельзя узнать, существует ли у сервера
// туннельный путь. Различать «не тот путь» и «не тот токен» — значит отдать
// проберу перебор пути.
//
// Метка connect-ip — особый случай. Снаружи мы WebTransport-сервер: это
// объявляют SETTINGS, это рассказывает сайт. Такой сервер о connect-ip не
// знает и отвечает на него, как на любую чужую метку, — 501. Мы же
// принимаем connect-ip от своих клиентов (штатный режим RFC 9484), и
// раньше постороннему на него доставался 404 — «метка знакома, не тот
// маршрут». Одним запросом с connect-ip и одним с выдуманной меткой пробер
// видел, что сервер понимает MASQUE, как бы ни выглядело всё остальное.
// Теперь посторонний с connect-ip получает ровно ответ на чужую метку, а
// различие появляется только с верным токеном, подделать который нельзя.

// allowedMethods — заголовок Allow в ответах 405 и OPTIONS. Перечислено то,
// что умеет сайт-прикрытие, и ничего больше: CONNECT в этом списке был бы
// ровно той подсказкой, которую мы убираем.
const allowedMethods = "GET, HEAD, OPTIONS"

// isExtendedCONNECT сообщает, есть ли у CONNECT псевдозаголовок :protocol.
// В http3 значение :protocol кладётся в Request.Proto; у классического
// CONNECT там остаётся «HTTP/3.0», а путь пуст (RFC 9114, §4.4).
func isExtendedCONNECT(r *http.Request) bool {
	return r.Method == http.MethodConnect && r.Proto != "" && r.Proto != "HTTP/3.0" && r.Proto != "HTTP/2.0"
}

// rejectCONNECT отвечает на CONNECT, который мы не приняли.
//
// Тело и заголовки — как у http.Error: короткий текст, nosniff. Именно так
// отвечает на нештатный запрос обычное приложение; развесистой страницы
// ошибки на CONNECT не отдаёт никто.
func rejectCONNECT(w http.ResponseWriter, code int) {
	if code == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", allowedMethods)
	}
	http.Error(w, http.StatusText(code), code)
}

// rejectStranger отвечает тому, кто не прошёл проверку: тем, что ответил бы
// WebTransport-сервер без такого маршрута. На webtransport — 404, как на
// любой несуществующий путь; на connect-ip — 501, как на любую метку,
// которой WebTransport-сервер не знает (см. выше).
func rejectStranger(w http.ResponseWriter, r *http.Request) {
	if r.Proto == ProtocolConnectIP {
		rejectCONNECT(w, http.StatusNotImplemented)
		return
	}
	rejectCONNECT(w, http.StatusNotFound)
}
