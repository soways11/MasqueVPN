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
