@echo off
REM build_to_exe_with_icon.bat
REM Place this file in C:\DevTools\ and add context menu to call it.
setlocal enabledelayedexpansion

if "%~1"=="" (
  echo [ERROR] No file provided.
  pause
  exit /b 1
)

set "SRC=%~1"
set "EXT=%~x1"
set "BASENAME=%~n1"
set "DIR=%~dp1"
set "DIST=%DIR%dist\%BASENAME%"
if not exist "%DIST%" mkdir "%DIST%"

REM find icon: 1) same-name .ico next to source, 2) C:\DevTools\icons\<basename>.ico, 3) C:\DevTools\icons\default.ico
set "ICON="
if exist "%DIR%%BASENAME%.ico" (
  set "ICON=%DIR%%BASENAME%.ico"
) else if exist "C:\DevTools\icons\%BASENAME%.ico" (
  set "ICON=C:\DevTools\icons\%BASENAME%.ico"
) else if exist "C:\DevTools\icons\default.ico" (
  set "ICON=C:\DevTools\icons\default.ico"
)

echo ===================================================
echo Building: %SRC%
if defined ICON ( echo Using icon: %ICON% ) else ( echo No icon found: will build without custom icon )
echo Output folder: %DIST%
echo ===================================================

REM ---------- Python ----------
if /I "%EXT%"==".py" (
  py -3 -m pip install --user --upgrade pip >nul 2>&1
  py -3 -m pip install --user pyinstaller >nul 2>&1
  if defined ICON (
    py -3 -m PyInstaller --clean --noconfirm --onefile --noupx --icon "%ICON%" --distpath "%DIST%" --workpath "%TEMP%\pyinst_work" --specpath "%TEMP%\pyinst_spec" "%SRC%" > "%DIST%\build.log" 2>&1
  ) else (
    py -3 -m PyInstaller --clean --noconfirm --onefile --noupx --distpath "%DIST%" --workpath "%TEMP%\pyinst_work" --specpath "%TEMP%\pyinst_spec" "%SRC%" > "%DIST%\build.log" 2>&1
  )
  if errorlevel 1 (
    echo [ERROR] PyInstaller failed. See %DIST%\build.log
    type "%DIST%\build.log"
    pause
  ) else (
    echo ✅ Built: "%DIST%\%BASENAME%.exe"
    explorer "%DIST%"
  )
  exit /b 0
)

REM ---------- PowerShell (.ps1) ----------
if /I "%EXT%"==".ps1" (
  echo Converting PowerShell to EXE...
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Try { if (-not (Get-Module -ListAvailable -Name ps2exe)) { Install-Module -Name ps2exe -Scope CurrentUser -Force } ; Import-Module ps2exe -ErrorAction Stop; Invoke-ps2exe -inputFile '%SRC%' -outputFile '%DIST%\\%BASENAME%.exe' -icon '%ICON%' -noConsole } Catch { Write-Error $_ }" > "%DIST%\build.log" 2>&1
  if errorlevel 1 (
    echo [ERROR] ps2exe failed. See %DIST%\build.log
    type "%DIST%\build.log"
    pause
  ) else (
    echo ✅ Built: "%DIST%\%BASENAME%.exe"
    explorer "%DIST%"
  )
  exit /b 0
)

REM ---------- Batch (.bat/.cmd) ----------
if /I "%EXT%"==".bat" (
  if exist "%ProgramFiles%\7-Zip\7z.exe" (
    set "TMP=%TEMP%\sfx_%BASENAME%"
    if exist "%TMP%" rd /s /q "%TMP%"
    mkdir "%TMP%"
    copy "%SRC%" "%TMP%" >nul
    pushd "%TMP%"
    "%ProgramFiles%\7-Zip\7z.exe" a -t7z payload.7z * > "%DIST%\7z.log" 2>&1
    set "SFX=%ProgramFiles%\7-Zip\7z.sfx"
    copy /b "%SFX%"+ "payload.7z" "%DIST%\%BASENAME%.exe" >nul
    popd
    rd /s /q "%TMP%"
    REM embed icon using rcedit.exe if present in C:\DevTools
    if defined ICON (
      if exist "C:\DevTools\rcedit.exe" (
        "C:\DevTools\rcedit.exe" "%DIST%\%BASENAME%.exe" --set-icon "%ICON%"
      ) else (
        echo [WARN] rcedit.exe not found in C:\DevTools. To embed icon, download rcedit.exe and place it in C:\DevTools.
      )
    )
    echo ✅ Built: "%DIST%\%BASENAME%.exe"
    explorer "%DIST%"
    exit /b 0
  ) else (
    echo [ERROR] 7-Zip not found in %ProgramFiles%\7-Zip. Install 7-Zip.
    pause
    exit /b 2
  )
)

REM ---------- Fallback: use rcedit to set icon if output exists ----------
REM If a tool produced EXE but without icon, try to set it
if exist "%DIST%\%BASENAME%.exe" (
  if defined ICON (
    if exist "C:\DevTools\rcedit.exe" (
      "C:\DevTools\rcedit.exe" "%DIST%\%BASENAME%.exe" --set-icon "%ICON%"
      echo ✅ Icon embedded.
    ) else (
      echo [WARN] rcedit.exe not found; place rcedit.exe in C:\DevTools to embed icons.
    )
  )
  explorer "%DIST%"
  exit /b 0
)

echo [ERROR] Unsupported extension or build failed: %EXT%
pause
exit /b 10
