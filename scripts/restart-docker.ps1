param(
  [int]$Port = 2048,
  [string]$Image = 'lufei-clashboard:latest',
  [string]$ContainerName = 'lufei-clashboard'
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DataDir = Join-Path $ProjectRoot 'data'

if ($Port -lt 1 -or $Port -gt 65535) {
  throw "Invalid port: $Port"
}

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

Push-Location $ProjectRoot
try {
  docker build -t $Image .
  docker rm -f $ContainerName 2>$null | Out-Null
  docker run -d `
    --name $ContainerName `
    --restart unless-stopped `
    -p "${Port}:2048" `
    -v "${DataDir}:/app/data" `
    -e PORT=2048 `
    $Image

  Write-Host ""
  Write-Host "Lufei-ClashBoard restarted."
  Write-Host "URL: http://127.0.0.1:$Port"
  Write-Host "Persistent data: $DataDir"
}
finally {
  Pop-Location
}
