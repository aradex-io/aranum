@echo off
REM ============================================================================
REM  Get-WeakPassword.cmd - double-click / console launcher for the scanner.
REM
REM  WHY THIS EXISTS: double-clicking a .ps1 on Windows does NOT run it - the
REM  shell only OPENS it in an editor or a document viewer (that "cannot open
REM  the file" message). Double-click THIS .cmd instead, or run it from a
REM  console. It invokes Get-WeakPassword.ps1 with a PER-PROCESS execution
REM  policy bypass (the -ExecutionPolicy parameter; nothing system-wide is
REM  changed), read-only.
REM
REM  No arguments (plain double-click) -> scans this machine's shell history +
REM  common logs (-History). Any arguments you pass are handed straight to the
REM  script, e.g.:
REM      Get-WeakPassword.cmd -Path C:\inetpub\logs -SecretsOnly
REM      Get-WeakPassword.cmd -History -OutFile C:\audit\pwhits.csv
REM
REM  Prefers PowerShell 7+ (pwsh) when installed, else Windows PowerShell 5.1.
REM  Authorized testing / internal compliance only (see README / CLAUDE.md).
REM ============================================================================
setlocal
set "PS1=%~dp0Get-WeakPassword.ps1"

if not exist "%PS1%" (
    echo ERROR: cannot find Get-WeakPassword.ps1 next to this launcher.
    echo Expected: "%PS1%"
    pause
    exit /b 2
)

set "PSEXE=powershell"
where pwsh >nul 2>&1 && set "PSEXE=pwsh"

if "%~1"=="" (
    "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -History
) else (
    "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
)
set "RC=%ERRORLEVEL%"

echo.
echo === scan complete ^(exit %RC%: 0=clean, 1=findings, 2=nothing-scanned^) ===
REM Keep the window open on a double-click so results stay readable.
pause
endlocal & exit /b %RC%
