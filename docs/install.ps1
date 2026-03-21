$ErrorActionPreference = 'Stop'

$repo       = 'it-atelier-gn/desktop-secrets'
$installDir = "$env:LOCALAPPDATA\desktop-secrets\bin"

Write-Host "Fetching latest release..."
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name
Write-Host "Installing DesktopSecrets $version"

New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$tmpDir  = Join-Path $env:TEMP "desktop-secrets-install"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

# Download SHA256SUMS
$sumsFile = Join-Path $tmpDir 'SHA256SUMS'
Invoke-WebRequest -Uri "https://github.com/$repo/releases/download/$version/SHA256SUMS" -OutFile $sumsFile

foreach ($bin in @('tplenv', 'getsec')) {
    $filename = "$bin-$version-windows-amd64.exe"
    $url      = "https://github.com/$repo/releases/download/$version/$filename"
    $tmpFile  = Join-Path $tmpDir $filename
    $dest     = Join-Path $installDir "$bin.exe"

    Write-Host "Downloading $bin..."
    Invoke-WebRequest -Uri $url -OutFile $tmpFile

    $actual   = (Get-FileHash -Algorithm SHA256 $tmpFile).Hash.ToLower()
    $line     = Get-Content $sumsFile | Where-Object { $_ -match [regex]::Escape($filename) }
    $expected = ($line -split '\s+')[0]

    if ($actual -ne $expected) {
        Write-Error "Checksum mismatch for $filename`n  expected: $expected`n  got:      $actual"
        exit 1
    }

    Move-Item -Force $tmpFile $dest
    Write-Host "  -> $dest"
}

Remove-Item -Recurse -Force $tmpDir

# Add to user PATH if not already present
$userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable('PATH', "$userPath;$installDir", 'User')
    Write-Host ""
    Write-Host "Added $installDir to your PATH."
    Write-Host "Restart your terminal for the change to take effect."
}

Write-Host ""
Write-Host "DesktopSecrets $version installed successfully."
Write-Host "Run 'tplenv --help' or 'getsec --help' to get started."
