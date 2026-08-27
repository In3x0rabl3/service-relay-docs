@echo off
:: Fix CRYPT_E_REVOCATION_OFFLINE errors for SOCKS proxy
:: Run as Administrator for best results

echo Disabling certificate revocation checks...

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 0 /f >nul 2>&1

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Certificate revocation checks disabled.
    echo SOCKS proxy should now work with HTTPS sites.
    echo.
    echo To restore defaults later, run: fix-ssl-revocation.bat /restore
) else (
    echo [ERROR] Failed to update registry. Try running as Administrator.
)

if "%1"=="/restore" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 1 /f >nul 2>&1
    echo.
    echo Certificate revocation checks restored to default.
)

echo.
pause
