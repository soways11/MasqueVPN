# Привязки ядра к Java (сверено 2026-09-26)

Ошибка в API ядра проявляется не там, где сделана: `gomobile bind` откажется
собирать привязку на машине с NDK, а до неё код может дожить внешне
исправным. Поэтому API сверен `gobind`-ом отдельно — он чистый Go и NDK не
требует, а значит проверка возможна и там, где Android собрать нечем.

Этот файл — ещё и эталон для теста `mobile/androidcheck`: он проверяет, что
каждый метод ядра, который зовёт Kotlin, здесь есть. Поменяли API — обновите
список ниже тем, что выдаст gobind.

Как повторить:

```sh
git clone https://github.com/golang/mobile /tmp/mobile-src
cd /tmp/mobile-src
# для go1.24 — коммит до перехода на 1.25:
git checkout 923679e
# если golang.org недоступен — в go.mod replace golang.org/x/{exp/shiny,image,
# mod,sync,sys,tools} на github.com/golang/* тех же версий, затем:
GOPROXY=direct GOSUMDB=off GOFLAGS=-mod=mod go build -o /tmp/gobind ./cmd/gobind

cd <корень репозитория>
/tmp/gobind -lang=java -outdir=/tmp/bindout github.com/soways11/masquevpn/mobile/core
```

(Жалоба на отсутствие `golang.org/x/mobile/bind` относится к генерации
go-шной обвязки и на Java-часть не влияет.)

## Что получилось

```java
public abstract class Core {
    public static final long   FieldNone     = 0L;
    public static final long   FieldServer   = 1L;
    public static final long   FieldAuthKey  = 2L;
    public static final long   FieldClientID = 3L;
    public static final String StateConnecting = "connecting";
    public static final String StateError      = "error";
    public static final String StateReady      = "ready";
    public static final String StateRunning    = "running";
    public static final String StateStopped    = "stopped";
    public static native Tunnel   newTunnel();
    public static native Profiles loadProfiles(String stored) throws Exception;
    public static native String   parseShared(String text);
    public static native boolean  isLink(String text);
}

public interface Protector {
    boolean protect(long fd);
}

public interface Events {
    void onState(String state);
    void onLog(String level, String message);
    void onRebind(String networkJSON);
}

public final class Tunnel {
    public native void   setDeviceID(String id);
    public native void   setStateDir(String dir);
    public native String connect(String configJSON, Protector p1, Events ev) throws Exception;
    public native void   attach(long fd) throws Exception;
    public native void   rebind(long fd) throws Exception;
    public native void   stop();
    public native String state();
    public native String statsJSON();
    public native String networkJSON();
}

public final class Profiles {
    public native String json();
    public native long   count();
    public native String current();
    public native String listJSON();
    public native String currentConfig();
    public native String fieldsJSON(String name);
    public native String add(String server, String authKey, String clientID, String name);
    public native String update(String old, String server, String authKey, String clientID, String name);
    public native void   select(String name) throws Exception;
    public native void   remove(String name) throws Exception;
    public native void   rename(String old, String name) throws Exception;
    public native String linkFor(String name) throws Exception;
}
```

Из этого следует несколько вещей, которые иначе пришлось бы угадывать:

- `Protector` и `Events` — **интерфейсы**, значит в Kotlin это
  `object : Protector { … }`, без скобок конструктора.
- Go-шный `int` становится **`long`**: дескриптор уходит как `fd.toLong()`,
  а приходит в `protect` как `long` и нуждается в `.toInt()` для
  `VpnService.protect`. Так же `count()` — `long`, сравнивать с `0L`.
- Константы полей формы тоже `long`, а в ответах формы (JSON) поле — `int`.
- Функция названа `NewTunnel`, а не `New`, — «new» в Java зарезервировано.
- Операции формы (`add`, `update`, `parseShared`) возвращают JSON, а не
  бросают исключение: gomobile переносит в исключение только текст, а форме
  нужно ещё и поле, которое подсветить —
  `{"ok":false,"error":"…","field":2}`.
- Описание сети (`network`) наружу не торчит: gomobile не умеет связывать
  срезы, поэтому оно едет JSON-ом, а тип намеренно не экспортирован.
