$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
& 'C:\Program Files\Go\bin\go.exe' mod tidy
& 'C:\Program Files\Go\bin\go.exe' build -trimpath -ldflags='-s -w' -o sentinel-agent.exe .
Write-Host "Built $PSScriptRoot\sentinel-agent.exe"
