@echo off
:: Run as Administrator to fix SSL revocation errors
:: This disables certificate revocation checking system-wide

echo Fixing SSL revocation errors...
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Please run as Administrator!
    echo Right-click this file and select "Run as administrator"
    pause
    exit /b 1
)

:: Disable revocation checking - User settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing" /v State /t REG_DWORD /d 146944 /f

:: Disable revocation checking - Machine settings (requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v CertificateRevocation /t REG_DWORD /d 0 /f

:: Disable OCSP
reg add "HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" /v DisableRootAutoUpdate /t REG_DWORD /d 1 /f

:: Chrome specific - disable revocation
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v EnableOnlineRevocationChecks /t REG_DWORD /d 0 /f

:: Edge specific
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EnableOnlineRevocationChecks /t REG_DWORD /d 0 /f

:: Restart crypto services to apply changes
echo.
echo Restarting crypto services...
net stop cryptsvc /y >nul 2>&1
net start cryptsvc >nul 2>&1

echo.
echo Done! SSL revocation checking disabled.
echo.
echo IMPORTANT: Close and reopen your browser for changes to take effect.
echo.
pause
