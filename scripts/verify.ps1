$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$pytest = Join-Path $repoRoot ".venv\Scripts\pytest.exe"
$ruff = Join-Path $repoRoot ".venv\Scripts\ruff.exe"
$results = @()

Write-Host "`n=== VulnScribe verification ===" -ForegroundColor Cyan
Write-Host "Repository: $repoRoot"

foreach ($tool in @(
    @{ Name = "pytest"; Path = $pytest; Args = @() },
    @{ Name = "ruff"; Path = $ruff; Args = @("check", ".") }
)) {
    if (-not (Test-Path $tool.Path)) {
        Write-Host "FAIL: $($tool.Name) not found at $($tool.Path)" -ForegroundColor Red
        $results += "$($tool.Name): FAIL (executable missing)"
        continue
    }

    Write-Host "`n=== $($tool.Name) ===" -ForegroundColor Cyan
    try {
        if ($tool.Name -eq "pytest") {
            & $tool.Path
        } else {
            & $tool.Path @($tool.Args)
        }

        $exitCode = $LASTEXITCODE
    } catch {
        Write-Host "Invocation failed: $_" -ForegroundColor Red
        $exitCode = 1
    }

    if ($exitCode -eq 0) {
        $results += "$($tool.Name): PASS"
    } else {
        $results += "$($tool.Name): FAIL (exit code $exitCode)"
    }
}

Write-Host "`n=== git diff --check ===" -ForegroundColor Cyan
try {
    git diff --check
    $gitExitCode = $LASTEXITCODE
} catch {
    Write-Host "Invocation failed: $_" -ForegroundColor Red
    $gitExitCode = 1
}
if ($gitExitCode -eq 0) {
    $results += "git diff --check: PASS"
} else {
    $results += "git diff --check: FAIL (exit code $gitExitCode)"
}

Write-Host "`n=== Git status (tracked and untracked) ===" -ForegroundColor Cyan
try {
    git status --short
    $statusExitCode = $LASTEXITCODE
} catch {
    Write-Host "Invocation failed: $_" -ForegroundColor Red
    $statusExitCode = 1
}
if ($statusExitCode -eq 0) {
    $results += "git status: PASS"
} else {
    $results += "git status: FAIL (exit code $statusExitCode)"
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$results | ForEach-Object {
    if ($_ -like "*: PASS") {
        Write-Host $_ -ForegroundColor Green
    } else {
        Write-Host $_ -ForegroundColor Red
    }
}

if (($results | Where-Object { $_ -like "*: FAIL*" }).Count -gt 0) {
    exit 1
}
