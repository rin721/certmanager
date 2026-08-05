$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    function Invoke-Checked([string]$label, [scriptblock]$command) {
        Write-Host "==> $label" -ForegroundColor Cyan
        & $command
        if ($LASTEXITCODE -ne 0) {
        throw "$label failed (exit code $LASTEXITCODE)"
        }
    }

    $goFiles = Get-ChildItem -Path (Join-Path $root 'cmd'), (Join-Path $root 'internal'), (Join-Path $root 'migrations') -Recurse -Filter '*.go' -File | Select-Object -ExpandProperty FullName
    $gofmtOutput = gofmt -l $goFiles
    if ($LASTEXITCODE -ne 0) { throw 'gofmt check failed' }
    if ($gofmtOutput) { throw ('Unformatted Go files:' + [Environment]::NewLine + ($gofmtOutput -join [Environment]::NewLine)) }

    Invoke-Checked 'Go tests' { go test ./... }
    Invoke-Checked 'Go vet' { go vet ./... }

    Push-Location (Join-Path $root 'web')
    try {
        Invoke-Checked 'Frontend lint' { npm run lint }
        Invoke-Checked 'Frontend unit tests' { npm run test }
        Invoke-Checked 'Frontend build' { npm run build }
    } finally {
        Pop-Location
    }

    if (Get-Command govulncheck -ErrorAction SilentlyContinue) {
        Invoke-Checked 'Go vulnerability scan' { govulncheck ./... }
    } else {
        Write-Warning 'govulncheck was not found; run the security scan from README manually.'
    }

    Push-Location (Join-Path $root 'web')
    try {
        Invoke-Checked 'npm high-severity audit' { npm audit --audit-level=high --registry=https://registry.npmjs.org }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}
