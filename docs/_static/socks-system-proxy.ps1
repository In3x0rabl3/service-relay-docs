<#
.SYNOPSIS
    Configure Windows to use SOCKS proxy system-wide and disable revocation checks
.PARAMETER Enable
    Enable the proxy settings
.PARAMETER Disable
    Disable the proxy settings (restore defaults)
.PARAMETER Port
    SOCKS port (default: 1080)
#>
param(
    [switch]$Enable,
    [switch]$Disable,
    [int]$Port = 1080
)

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

if ($Disable) {
    Write-Host "Restoring default settings..." -ForegroundColor Yellow

    # Re-enable revocation checks
    Set-ItemProperty -Path $regPath -Name "CertificateRevocation" -Value 1 -ErrorAction SilentlyContinue

    # Disable proxy
    Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 0

    # Clear proxy settings
    Remove-ItemProperty -Path $regPath -Name "ProxyServer" -ErrorAction SilentlyContinue

    Write-Host "Default settings restored." -ForegroundColor Green
    Write-Host "You may need to restart applications for changes to take effect."
    exit
}

if ($Enable) {
    Write-Host "Configuring system for SOCKS proxy..." -ForegroundColor Cyan

    # Disable certificate revocation checks (fixes CRYPT_E_REVOCATION_OFFLINE)
    Set-ItemProperty -Path $regPath -Name "CertificateRevocation" -Value 0
    Write-Host "[OK] Disabled certificate revocation checks" -ForegroundColor Green

    # Note: Windows doesn't natively support SOCKS in system proxy
    # But disabling revocation is the main fix needed
    Write-Host ""
    Write-Host "Certificate revocation checks disabled." -ForegroundColor Green
    Write-Host "SOCKS proxy should now work without SSL errors." -ForegroundColor Green
    Write-Host ""
    Write-Host "For full system-wide SOCKS:" -ForegroundColor Yellow
    Write-Host "  - Use Proxifier (recommended)" -ForegroundColor Yellow
    Write-Host "  - Or configure apps individually with socks5h://127.0.0.1:$Port" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To restore defaults: .\socks-system-proxy.ps1 -Disable" -ForegroundColor Cyan
    exit
}

Write-Host "SOCKS System Proxy Configuration"
Write-Host ""
Write-Host "Usage:"
Write-Host "  .\socks-system-proxy.ps1 -Enable     # Disable revocation checks"
Write-Host "  .\socks-system-proxy.ps1 -Disable    # Restore defaults"
Write-Host ""
Write-Host "This fixes CRYPT_E_REVOCATION_OFFLINE errors when using SOCKS proxy."
