; Установщик masquevpn для Windows (NSIS 3).
;
; Собирается build-installer.sh — прямо в Linux, makensis кроссплатформенный.
; Здесь только то, что относится к установке; сами программы собирает скрипт.
;
; Что делает установщик:
;   - кладёт masquevpn.exe, masquevpn-cli.exe и wintun.dll в Program Files;
;   - ярлыки в «Пуск» (и, по желанию, на рабочий стол) для всех пользователей;
;   - запись в «Установка и удаление программ»;
;   - закрывает запущенное окно штатно (WM_CLOSE — туннель отключается сам,
;     а не обрывается убийством процесса);
;   - переносит профили из папки, откуда запущен: так переходят с
;     «папки из архива» на установленную программу, не теряя доступов;
;   - если был включён автозапуск, перенаправляет его на новое место.
;
; Удаление убирает следы в системе (masquevpn-cli -cleanup), задачу
; автозапуска и файлы; профили с ключами — только если человек согласится.

Unicode true
; Установщик сам 64-битный, как и программа. 32-битный (умолчание NSIS)
; работал бы через WoW64, где Windows подменяет пути и ветки реестра, — и
; каждое обращение пришлось бы разворачивать обратно. 32-битной Windows
; программа всё равно не поддерживает.
Target amd64-unicode
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "WinMessages.nsh"

!ifndef VERSION
  !define VERSION "0.2.0"
!endif
!ifndef VERSION4
  !define VERSION4 "0.2.0.0"
!endif
!ifndef SRC
  !define SRC "."
!endif
!ifndef OUT
  !define OUT "."
!endif

!define APP        "masquevpn"
!define WNDCLASS   "masquevpnWindow"
!define TASK       "masquevpn"
!define TASK_OLD   "govpn"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APP}"

Name "${APP}"
OutFile "${OUT}\${APP}-setup-${VERSION}.exe"
InstallDir "$PROGRAMFILES64\${APP}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APP} ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${VERSION4}"
VIFileVersion "${VERSION4}"
VIAddVersionKey /LANG=1049 "ProductName" "${APP}"
VIAddVersionKey /LANG=1049 "FileDescription" "Установка ${APP} — VPN на MASQUE"
VIAddVersionKey /LANG=1049 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=1049 "CompanyName" "${APP}"
VIAddVersionKey /LANG=1049 "LegalCopyright" "${APP}"

!define MUI_ICON   "${SRC}\masquevpn.ico"
!define MUI_UNICON "${SRC}\masquevpn.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TEXT "Будет установлен ${APP} ${VERSION} — клиент VPN на MASQUE (CONNECT-IP поверх HTTP/3).$\r$\n$\r$\nЕсли ${APP} запущен, установщик его закроет: туннель на время установки отключится.$\r$\n$\r$\nПрофили из папки, откуда запущена установка, перенесутся сами."
!define MUI_COMPONENTSPAGE_NODESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP}.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить ${APP}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"

; ---------- закрыть запущенное окно ----------
;
; WM_CLOSE, а не завершение процесса: окно по нему останавливает туннель и
; прибирается (маршруты, блокировка сети, правило имён). Убитый процесс
; оставил бы это до следующего запуска. Ждём до 15 секунд: остановка
; туннеля ограничена 5 секундами, остальное — запас.
!macro CloseApp UN
Function ${UN}CloseApp
  FindWindow $0 "${WNDCLASS}"
  ${If} $0 = 0
    Return
  ${EndIf}
  MessageBox MB_OKCANCEL|MB_ICONINFORMATION "${APP} запущен и будет закрыт — туннель отключится." /SD IDOK IDOK close
  Abort
  close:
  DetailPrint "Закрываю ${APP}…"
  SendMessage $0 ${WM_CLOSE} 0 0 /TIMEOUT=5000
  StrCpy $1 0
  ${Do}
    Sleep 250
    FindWindow $0 "${WNDCLASS}"
    ${If} $0 = 0
      ${Break}
    ${EndIf}
    IntOp $1 $1 + 1
    ${If} $1 >= 60
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "${APP} не закрывается. Закройте его сами и нажмите «Повтор»." /SD IDCANCEL IDRETRY retry
      Abort
      retry:
      StrCpy $1 0
    ${EndIf}
  ${Loop}
  ; Окно исчезло, процесс ещё может дописывать уборку и держать файлы.
  Sleep 1000
FunctionEnd
!macroend
!insertmacro CloseApp ""
!insertmacro CloseApp "un."

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "${APP} работает только в 64-битной Windows." /SD IDOK
    Abort
  ${EndIf}
  ; Обновление ставится туда же, где стоит прежняя версия.
  SetRegView 64
  ReadRegStr $0 HKLM "${UNINST_KEY}" "InstallLocation"
  ${If} $0 != ""
    StrCpy $INSTDIR $0
  ${EndIf}
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

; ---------- установка ----------

Section "${APP}" SecMain
  SectionIn RO
  SetShellVarContext all
  Call CloseApp

  SetOutPath "$INSTDIR"
  File "${SRC}\build\${APP}.exe"
  File "${SRC}\build\${APP}-cli.exe"
  File "${SRC}\wintun\amd64\wintun.dll"

  ; Профили из папки, откуда запущен установщик. Только если в месте
  ; установки их ещё нет: при обновлении чужой копией не затираем.
  ${IfNot} ${FileExists} "$INSTDIR\profiles.json"
  ${AndIf} ${FileExists} "$EXEDIR\profiles.json"
    CopyFiles /SILENT "$EXEDIR\profiles.json" "$INSTDIR"
    DetailPrint "Профили перенесены из $EXEDIR"
    ; Псевдоним устройства — вместе с профилями, иначе сервер увидит это
    ; устройство новым и выдаст ему другой адрес.
    ${IfNot} ${FileExists} "$INSTDIR\device.id"
    ${AndIf} ${FileExists} "$EXEDIR\device.id"
      CopyFiles /SILENT "$EXEDIR\device.id" "$INSTDIR"
    ${EndIf}
  ${EndIf}

  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortcut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\${APP}.exe"

  ; Автозапуск был включён в прежней копии — задача указывает на старое
  ; место. Перенаправляем на установленную программу, иначе при входе
  ; запускалась бы старая.
  nsExec::Exec 'schtasks /Query /TN "${TASK}"'
  Pop $0
  ${If} $0 = 0
    nsExec::Exec 'schtasks /Create /TN "${TASK}" /TR "\"$INSTDIR\${APP}.exe\"" /SC ONLOGON /RL HIGHEST /F'
    Pop $0
    DetailPrint "Автозапуск перенаправлен на $INSTDIR"
  ${EndIf}

  SetRegView 64
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayName"          "${APP}"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayVersion"       "${VERSION}"
  WriteRegStr   HKLM "${UNINST_KEY}" "Publisher"            "${APP}"
  WriteRegStr   HKLM "${UNINST_KEY}" "DisplayIcon"          "$INSTDIR\${APP}.exe,0"
  WriteRegStr   HKLM "${UNINST_KEY}" "InstallLocation"      "$INSTDIR"
  WriteRegStr   HKLM "${UNINST_KEY}" "UninstallString"      '"$INSTDIR\uninstall.exe"'
  WriteRegStr   HKLM "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${UNINST_KEY}" "EstimatedSize" $0
SectionEnd

Section "Ярлык на рабочем столе" SecDesktop
  SetShellVarContext all
  CreateShortcut "$DESKTOP\${APP}.lnk" "$INSTDIR\${APP}.exe"
SectionEnd

; ---------- удаление ----------

Section "Uninstall"
  SetShellVarContext all
  Call un.CloseApp

  ; Следы в системе, которые мог оставить упавший клиент: блокировка сети,
  ; правило разрешения имён, маршруты. Штатно закрытое окно их уже убрало —
  ; тогда команда просто скажет, что убирать нечего.
  ${If} ${FileExists} "$INSTDIR\${APP}-cli.exe"
    nsExec::ExecToLog '"$INSTDIR\${APP}-cli.exe" -cleanup'
    Pop $0
  ${EndIf}
  ; Автозапуск — и под нынешним, и под прежним именем проекта.
  nsExec::Exec 'schtasks /Delete /TN "${TASK}" /F'
  Pop $0
  nsExec::Exec 'schtasks /Delete /TN "${TASK_OLD}" /F'
  Pop $0

  Delete "$INSTDIR\${APP}.exe"
  Delete "$INSTDIR\${APP}-cli.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\${APP}-crash.txt"
  Delete "$INSTDIR\${APP}-trace.txt"
  Delete "$SMPROGRAMS\${APP}.lnk"
  Delete "$DESKTOP\${APP}.lnk"

  ; Профили с ключами — не молча. По умолчанию «Нет»: переустановка не должна
  ; стоить доступов, а тихое удаление (/S) их тем более не трогает.
  ${If} ${FileExists} "$INSTDIR\profiles.json"
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Удалить и профили с ключами доступа?$\r$\n$\r$\nЕсли оставить, они подхватятся при следующей установке." /SD IDNO IDNO keep
    Delete "$INSTDIR\profiles.json"
    Delete "$INSTDIR\device.id"
    Delete "$INSTDIR\client.json"
    keep:
  ${EndIf}

  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"  ; только если пусто — профили, если остались, не трогаем

  DeleteRegKey HKLM "${UNINST_KEY}"
SectionEnd
