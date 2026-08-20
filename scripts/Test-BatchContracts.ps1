#Requires -Version 5.1
# Copyright 2026 Julien Bombled
# Licensed under the Apache License, Version 2.0.
<#
.SYNOPSIS
    Verifies repository batch entry-point safety contracts with local stubs.
.DESCRIPTION
    Creates disposable fixtures and substitutes Git, GitHub CLI, rustup, and
    PowerShell so no real network, tag, elevation, or repository mutation occurs.
.NOTES
    Exit code 0 means every contract passed; an assertion failure returns non-zero.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$tempRoot = Join-Path $tempParent ("winprofile-batch-contracts-{0}" -f [guid]::NewGuid().ToString('N'))
$headSha = '40072747c645edb20b78d4be851edc2bfcee5d57'
$otherSha = '1111111111111111111111111111111111111111'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-ExitCode {
    param($Result, [int]$Expected, [string]$Context)
    if ($Result.ExitCode -ne $Expected) {
        throw "$Context returned $($Result.ExitCode), expected $Expected.`n$($Result.Output)"
    }
}

function Assert-NoStatusTemporaryFile {
    param([string]$Fixture, [string]$Context)
    $items = @(Get-ChildItem -LiteralPath (Join-Path $Fixture 'temp') -Filter 'winprofile-*-git-status-*')
    Assert-True ($items.Count -eq 0) "$Context left a temporary Git status container."
}

function Write-AsciiFile {
    param([string]$Path, [string[]]$Lines)
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    [IO.File]::WriteAllLines($Path, $Lines, [Text.Encoding]::ASCII)
}

function Initialize-Fixture {
    param([string]$Name, [switch]$GitWorktree)
    $path = Join-Path $tempRoot $Name
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    foreach ($directory in @('scripts', 'stubs', 'docs', 'work-private-docs', 'temp')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $path $directory) | Out-Null
    }
    if ($GitWorktree) { New-Item -ItemType Directory -Path (Join-Path $path '.git') | Out-Null }
    Write-AsciiFile -Path (Join-Path $path 'Cargo.toml') -Lines @(
        '[workspace.package]',
        'version = "2026.819.0"'
    )
    Write-AsciiFile -Path (Join-Path $path 'docs/release-v2026.819.0.md') -Lines @('# fixture')
    return $path
}

function Copy-ProductScript {
    param([string]$Fixture, [string]$RelativePath)
    $destination = Join-Path $Fixture $RelativePath
    $parent = Split-Path -Parent $destination
    if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    Copy-Item -LiteralPath (Join-Path $repoRoot $RelativePath) -Destination $destination -Force
}

function Initialize-RunFixture {
    param([string]$Name)
    $fixture = Initialize-Fixture -Name $Name -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $fixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $fixture
    return $fixture
}

function Write-ToolStub {
    param([string]$Fixture)
    $stubRoot = Join-Path $Fixture 'stubs'
    Write-AsciiFile -Path (Join-Path $stubRoot 'rustup.cmd') -Lines @(
        '@echo off',
        '>>"%WINPROFILE_TEST_LOG%" echo rustup %*',
        '>>"%WINPROFILE_TEST_LOG%" echo target=%CARGO_TARGET_DIR%',
        '>>"%WINPROFILE_TEST_LOG%" echo slint=%SLINT_EMIT_DEBUG_INFO%',
        'if /i "%~1 %~2"=="toolchain list" (echo 1.97.1-x86_64-pc-windows-gnu& exit /b 0)',
        'if /i "%~1"=="run" if /i "%~4"=="build" (',
        '  if not exist "%CARGO_TARGET_DIR%\debug" mkdir "%CARGO_TARGET_DIR%\debug"',
        '  type nul > "%CARGO_TARGET_DIR%\debug\winprofile-admin.exe"',
        ')',
        'if /i "%~1"=="run" if /i "%~4"=="--version" echo cargo 1.97.1 (fixture)',
        'exit /b 0'
    )
    Write-AsciiFile -Path (Join-Path $stubRoot 'powershell.cmd') -Lines @(
        '@echo off',
        '>>"%WINPROFILE_TEST_LOG%" echo powershell %*',
        '>>"%WINPROFILE_TEST_LOG%" echo slint=%SLINT_EMIT_DEBUG_INFO%',
        'exit /b 0'
    )
    Write-AsciiFile -Path (Join-Path $stubRoot 'git.cmd') -Lines @(
        '@echo off',
        'setlocal EnableDelayedExpansion',
        '>>"%WINPROFILE_TEST_LOG%" echo git %*',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="--is-inside-work-tree" (echo true& exit /b 0)',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="--abbrev-ref" (echo main& exit /b 0)',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="--short" (echo 4007274& exit /b 0)',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="origin/main" (echo %WINPROFILE_TEST_HEAD_SHA%& exit /b 0)',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="HEAD" (',
        '  if defined WINPROFILE_TEST_RACE_FILE if exist "%WINPROFILE_TEST_RACE_FILE%" (echo %WINPROFILE_TEST_OTHER_SHA%& exit /b 0)',
        '  echo %WINPROFILE_TEST_HEAD_SHA%& exit /b 0',
        ')',
        'if /i "%~1"=="rev-parse" if /i "%~2"=="-q" exit /b 1',
        'if /i "%~1 %~2"=="branch --show-current" (echo main& exit /b 0)',
        'if /i "%~1 %~2"=="remote get-url" (',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="hostile-origin" (echo https://example.invalid/attacker/WinProfile.git& exit /b 0)',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="hostile-push" if /i "%~3"=="--push" (echo https://example.invalid/attacker/WinProfile.git& exit /b 0)',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="duplicate-origin" (echo https://github.com/VBlackJack/WinProfile.git& echo git@github.com:VBlackJack/WinProfile.git& exit /b 0)',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="official-ssh" (echo git@github.com:VBlackJack/WinProfile.git& exit /b 0)',
        '  echo https://github.com/VBlackJack/WinProfile.git& exit /b 0',
        ')',
        'if /i "%~1"=="fetch" (',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="fetch-failure" exit /b 1',
        '  exit /b 0',
        ')',
        'if /i "%~1"=="pull" exit /b 0',
        'if /i "%~1 %~2"=="status --porcelain" (',
        '  if defined WINPROFILE_TEST_STATUS_COUNT_FILE (',
        '    set "STATUS_COUNT=0"',
        '    if exist "%WINPROFILE_TEST_STATUS_COUNT_FILE%" set /p STATUS_COUNT=<"%WINPROFILE_TEST_STATUS_COUNT_FILE%"',
        '    set /a STATUS_COUNT+=1',
        '    >"%WINPROFILE_TEST_STATUS_COUNT_FILE%" echo !STATUS_COUNT!',
        '    if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="second-status-failure" if "!STATUS_COUNT!"=="2" exit /b 1',
        '  )',
        '  if /i "%WINPROFILE_TEST_GIT_SCENARIO%"=="status-failure" exit /b 1',
        '  if defined WINPROFILE_TEST_STATUS_RESIDUE_FILE >"%WINPROFILE_TEST_STATUS_RESIDUE_FILE%" echo blocker',
        '  if defined WINPROFILE_TEST_DIRTY_FILE if exist "%WINPROFILE_TEST_DIRTY_FILE%" echo  M changed.txt',
        '  exit /b 0',
        ')',
        'if /i "%~1"=="show-ref" exit /b 0',
        'if /i "%~1"=="rev-list" (',
        '  if /i "%WINPROFILE_TEST_GRAPH_SCENARIO%"=="behind" (',
        '    if /i "%~3"=="HEAD..origin/main" (echo 1) else echo 0',
        '    exit /b 0',
        '  )',
        '  if /i "%WINPROFILE_TEST_GRAPH_SCENARIO%"=="ahead" (',
        '    if /i "%~3"=="origin/main..HEAD" (echo 1) else echo 0',
        '    exit /b 0',
        '  )',
        '  if /i "%WINPROFILE_TEST_GRAPH_SCENARIO%"=="diverged" (echo 1& exit /b 0)',
        '  echo 0& exit /b 0',
        ')',
        'if /i "%~1"=="log" (echo fixture subject& exit /b 0)',
        'if /i "%~1"=="ls-remote" exit /b 2',
        'if /i "%~1"=="tag" exit /b 0',
        'if /i "%~1"=="push" exit /b 0',
        'exit /b 1'
    )
    Write-AsciiFile -Path (Join-Path $stubRoot 'gh.cmd') -Lines @(
        '@echo off',
        '>>"%WINPROFILE_TEST_LOG%" echo gh %*',
        'if /i "%~1 %~2"=="run list" (echo success& exit /b 0)',
        'if /i "%~1 %~2"=="secret list" (',
        '  if /i "%WINPROFILE_TEST_GH_SCENARIO%"=="prefix-only" (',
        '    echo WINDOWS_SIGNING_CERTIFICATE_BASE64_OLD',
        '    echo WINDOWS_SIGNING_CERTIFICATE_PASSWORD_OLD',
        '    echo WINDOWS_SIGNING_TIMESTAMP_URL_OLD',
        '    exit /b 0',
        '  )',
        '  echo WINDOWS_SIGNING_CERTIFICATE_BASE64',
        '  echo WINDOWS_SIGNING_CERTIFICATE_PASSWORD',
        '  echo WINDOWS_SIGNING_TIMESTAMP_URL',
        '  exit /b 0',
        ')',
        'exit /b 1'
    )
}

function Write-QualityStub {
    param([string]$Fixture)
    Write-AsciiFile -Path (Join-Path $Fixture 'Test.bat') -Lines @(
        '@echo off',
        '>>"%WINPROFILE_TEST_LOG%" echo quality %*',
        'if defined WINPROFILE_TEST_RACE_FILE type nul > "%WINPROFILE_TEST_RACE_FILE%"',
        'if defined WINPROFILE_TEST_DIRTY_FILE type nul > "%WINPROFILE_TEST_DIRTY_FILE%"',
        'if defined WINPROFILE_TEST_TAMPER_MARKER echo tampered>"%WINPROFILE_TEST_TAMPER_MARKER%"',
        'exit /b 0'
    )
}

function Write-ApprovalMarker {
    param([string]$Fixture, [string]$Commit = $headSha, [string[]]$AdditionalLines = @())
    $lines = @(
        'WINPROFILE_RELEASE_VM_APPROVAL_V1',
        'tag=v2026.819.0',
        "commit=$Commit",
        'result=approved'
    ) + $AdditionalLines
    Write-AsciiFile -Path (Join-Path $Fixture 'work-private-docs/release-v2026.819.0.approved') -Lines $lines
}

function Invoke-Batch {
    param(
        [string]$BatchPath,
        [string[]]$Arguments = @(),
        [hashtable]$Environment = @{},
        [string]$InputText = ''
    )
    $saved = @{}
    foreach ($key in $Environment.Keys) {
        $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], 'Process')
    }
    $inputFile = $null
    try {
        $quotedArguments = ($Arguments | ForEach-Object { '"{0}"' -f ($_ -replace '"', '""') }) -join ' '
        $redirection = '<nul'
        if ($InputText) {
            $inputFile = Join-Path $tempRoot ("input-{0}.txt" -f [guid]::NewGuid().ToString('N'))
            Write-AsciiFile -Path $inputFile -Lines @($InputText)
            $redirection = '<"{0}"' -f $inputFile
        }
        $command = 'call "{0}" {1} {2}' -f $BatchPath, $quotedArguments, $redirection
        $output = @(& cmd.exe /d /s /c $command 2>&1)
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Output = ($output -join [Environment]::NewLine)
        }
    }
    finally {
        if ($inputFile) { Remove-Item -LiteralPath $inputFile -Force -ErrorAction SilentlyContinue }
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process')
        }
    }
}

function Get-TestEnvironment {
    param([string]$Fixture, [string]$LogPath)
    return @{
        WINPROFILE_BATCH_TEST_MODE = '1'
        WINPROFILE_TEST_RUSTUP = (Join-Path $Fixture 'stubs/rustup.cmd')
        WINPROFILE_TEST_POWERSHELL = (Join-Path $Fixture 'stubs/powershell.cmd')
        WINPROFILE_TEST_GIT = (Join-Path $Fixture 'stubs/git.cmd')
        WINPROFILE_TEST_GH = (Join-Path $Fixture 'stubs/gh.cmd')
        WINPROFILE_TEST_LOG = $LogPath
        WINPROFILE_TEST_HEAD_SHA = $headSha
        WINPROFILE_TEST_OTHER_SHA = $otherSha
        TEMP = (Join-Path $Fixture 'temp')
        TMP = (Join-Path $Fixture 'temp')
    }
}

try {
    New-Item -ItemType Directory -Path $tempRoot | Out-Null

    $cargoFixture = Initialize-Fixture -Name 'cargo-build'
    Copy-ProductScript -Fixture $cargoFixture -RelativePath 'scripts/Cargo.bat'
    Copy-ProductScript -Fixture $cargoFixture -RelativePath 'Build.bat'
    Write-ToolStub -Fixture $cargoFixture
    $cargoLog = Join-Path $cargoFixture 'calls.log'
    $cargoEnvironment = Get-TestEnvironment -Fixture $cargoFixture -LogPath $cargoLog
    $cargoEnvironment.CARGO_TARGET_DIR = 'C:\hostile-external-target'
    $cargoResult = Invoke-Batch -BatchPath (Join-Path $cargoFixture 'scripts/Cargo.bat') -Arguments @('--version') -Environment $cargoEnvironment
    Assert-ExitCode $cargoResult 0 'Cargo wrapper'
    $cargoCalls = Get-Content -Raw -LiteralPath $cargoLog
    $expectedTarget = (Join-Path $cargoFixture 'target')
    Assert-True ($cargoCalls -match [regex]::Escape("target=$expectedTarget")) 'Cargo wrapper did not force the repository target directory.'
    Assert-True ($cargoCalls -match 'run "?1\.97\.1-x86_64-pc-windows-gnu"? cargo "?--version"?') "Cargo wrapper did not use the exact pinned GNU toolchain.`n$cargoCalls"

    Remove-Item -LiteralPath $cargoLog -ErrorAction SilentlyContinue
    $buildUnknown = Invoke-Batch -BatchPath (Join-Path $cargoFixture 'Build.bat') -Arguments @('typo', 'no-pause') -Environment $cargoEnvironment
    Assert-ExitCode $buildUnknown 2 'Build unknown argument'
    Assert-True (-not (Test-Path -LiteralPath $cargoLog)) 'Build invoked Cargo after an unknown argument.'
    Assert-True ($buildUnknown.Output -notmatch 'Appuyez|Press any key') 'Build ignored no-pause after an unknown argument.'
    $buildResult = Invoke-Batch -BatchPath (Join-Path $cargoFixture 'Build.bat') -Arguments @('no-pause') -Environment $cargoEnvironment
    Assert-ExitCode $buildResult 0 'Build no-pause'
    Assert-True (Test-Path -LiteralPath (Join-Path $cargoFixture 'target/debug/winprofile-admin.exe')) 'Build did not require the exact executable output.'

    $testFixture = Initialize-Fixture -Name 'test-args'
    Copy-ProductScript -Fixture $testFixture -RelativePath 'Test.bat'
    $testUnknown = Invoke-Batch -BatchPath (Join-Path $testFixture 'Test.bat') -Arguments @('typo', 'no-pause')
    Assert-ExitCode $testUnknown 2 'Test unknown argument'
    Assert-True ($testUnknown.Output -notmatch 'Appuyez|Press any key') 'Test ignored no-pause after an unknown argument.'
    Copy-ProductScript -Fixture $testFixture -RelativePath 'scripts/Cargo.bat'
    Write-ToolStub -Fixture $testFixture
    $testLog = Join-Path $testFixture 'calls.log'
    $testEnvironment = Get-TestEnvironment -Fixture $testFixture -LogPath $testLog
    $testEnvironment.SLINT_EMIT_DEBUG_INFO = 'hostile-inherited-value'
    $testResult = Invoke-Batch -BatchPath (Join-Path $testFixture 'Test.bat') -Arguments @('no-pause') -Environment $testEnvironment
    Assert-ExitCode $testResult 0 'Test Slint metadata scoping'
    $testCalls = Get-Content -Raw -LiteralPath $testLog
    Assert-True ($testCalls -match '(?m)^powershell .*Test-BatchContracts\.ps1"?\r?\nslint=\r?$') ('Test leaked Slint metadata into the batch-contract harness.' + [Environment]::NewLine + $testCalls)
    Assert-True ($testCalls -match '(?ms)rustup run .* cargo "?fmt"?.*?\r?\ntarget=.*?\r?\nslint=\r?\n') ('Test leaked Slint metadata into formatting.' + [Environment]::NewLine + $testCalls)
    Assert-True ($testCalls -match '(?ms)rustup run .* cargo "?clippy"?.*?\r?\ntarget=.*?\r?\nslint=\r?\n') ('Test leaked Slint metadata into Clippy.' + [Environment]::NewLine + $testCalls)
    Assert-True ($testCalls -match '(?ms)rustup run .* cargo "?test"?.*?\r?\ntarget=.*?\r?\nslint=1\r?\n') ('Test did not scope Slint metadata to workspace tests.' + [Environment]::NewLine + $testCalls)

    $runFixture = Initialize-Fixture -Name 'run-archive'
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) { Copy-ProductScript -Fixture $runFixture -RelativePath $relative }
    Write-ToolStub -Fixture $runFixture
    $runLog = Join-Path $runFixture 'calls.log'
    $runEnvironment = Get-TestEnvironment -Fixture $runFixture -LogPath $runLog
    $runUnknown = Invoke-Batch -BatchPath (Join-Path $runFixture 'Run.bat') -Arguments @('typo', 'no-pause') -Environment $runEnvironment
    Assert-ExitCode $runUnknown 2 'Run unknown argument'
    Assert-True (-not (Test-Path -LiteralPath $runLog)) 'Run invoked a tool after an unknown argument.'
    Assert-True ($runUnknown.Output -notmatch 'Appuyez|Press any key') 'Run ignored no-pause after an unknown argument.'
    $runConflict = Invoke-Batch -BatchPath (Join-Path $runFixture 'Run.bat') -Arguments @('pull', 'no-fetch', 'no-pause') -Environment $runEnvironment
    Assert-ExitCode $runConflict 2 'Run conflicting pull/no-fetch'
    Assert-True (-not (Test-Path -LiteralPath $runLog)) 'Run invoked a tool after contradictory arguments.'
    $runArchive = Invoke-Batch -BatchPath (Join-Path $runFixture 'Run.bat') -Arguments @('no-pause') -Environment $runEnvironment
    Assert-ExitCode $runArchive 0 'Run source archive without Git metadata'
    $runCalls = Get-Content -Raw -LiteralPath $runLog
    Assert-True ($runCalls -notmatch 'git (fetch|pull)') 'Offline Run performed a network Git command.'
    Assert-True ($runCalls -match 'powershell -NoProfile -Command') 'Run did not invoke the elevation shell through the seam.'
    Assert-True ($runCalls -notmatch 'ExecutionPolicy') 'Run restored the forbidden ExecutionPolicy bypass.'

    $hostileRunFixture = Initialize-Fixture -Name 'run-hostile' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) { Copy-ProductScript -Fixture $hostileRunFixture -RelativePath $relative }
    Write-ToolStub -Fixture $hostileRunFixture
    $hostileRunLog = Join-Path $hostileRunFixture 'calls.log'
    $hostileRunEnvironment = Get-TestEnvironment -Fixture $hostileRunFixture -LogPath $hostileRunLog
    $hostileRunEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'hostile-origin'
    $hostileRun = Invoke-Batch -BatchPath (Join-Path $hostileRunFixture 'Run.bat') -Arguments @('no-pause') -Environment $hostileRunEnvironment
    Assert-ExitCode $hostileRun 1 'Run hostile origin'
    $hostileRunCalls = Get-Content -Raw -LiteralPath $hostileRunLog
    Assert-True ($hostileRunCalls -notmatch 'git fetch') 'Run contacted a hostile origin.'
    Assert-True ($hostileRunCalls -notmatch 'powershell|rustup') 'Run built or elevated after rejecting a hostile origin.'

    $hostilePushRunFixture = Initialize-Fixture -Name 'run-hostile-push' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $hostilePushRunFixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $hostilePushRunFixture
    $hostilePushRunLog = Join-Path $hostilePushRunFixture 'calls.log'
    $hostilePushRunEnvironment = Get-TestEnvironment -Fixture $hostilePushRunFixture -LogPath $hostilePushRunLog
    $hostilePushRunEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'hostile-push'
    $hostilePushRun = Invoke-Batch -BatchPath (Join-Path $hostilePushRunFixture 'Run.bat') -Arguments @('no-pause') -Environment $hostilePushRunEnvironment
    Assert-ExitCode $hostilePushRun 1 'Run hostile push URL'
    $hostilePushRunCalls = Get-Content -Raw -LiteralPath $hostilePushRunLog
    Assert-True (([regex]::Matches($hostilePushRunCalls, 'git remote get-url')).Count -eq 2) 'Run did not inspect fetch and push URLs independently.'
    Assert-True ($hostilePushRunCalls -notmatch 'git (fetch|pull)|powershell|rustup') 'Run continued after rejecting a hostile push URL.'

    $offlineRunFixture = Initialize-Fixture -Name 'run-repository-offline' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) { Copy-ProductScript -Fixture $offlineRunFixture -RelativePath $relative }
    Write-ToolStub -Fixture $offlineRunFixture
    $offlineRunLog = Join-Path $offlineRunFixture 'calls.log'
    $offlineRunEnvironment = Get-TestEnvironment -Fixture $offlineRunFixture -LogPath $offlineRunLog
    $offlineRunEnvironment.WINPROFILE_TEST_GRAPH_SCENARIO = 'behind'
    $offlineRun = Invoke-Batch -BatchPath (Join-Path $offlineRunFixture 'Run.bat') -Arguments @('no-fetch', 'no-pause') -Environment $offlineRunEnvironment
    Assert-ExitCode $offlineRun 0 'Run no-fetch alone'
    $offlineRunCalls = Get-Content -Raw -LiteralPath $offlineRunLog
    Assert-True ($offlineRunCalls -notmatch 'git (fetch|pull|ls-remote|push)') 'no-fetch performed a Git network operation.'

    $noPullFixture = Initialize-Fixture -Name 'run-no-pull' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $noPullFixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $noPullFixture
    $noPullLog = Join-Path $noPullFixture 'calls.log'
    $noPullEnvironment = Get-TestEnvironment -Fixture $noPullFixture -LogPath $noPullLog
    $noPullEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'official-ssh'
    $noPullResult = Invoke-Batch -BatchPath (Join-Path $noPullFixture 'Run.bat') -Arguments @('no-pull', 'no-pause') -Environment $noPullEnvironment
    Assert-ExitCode $noPullResult 0 'Run no-pull with official SSH origin'
    $noPullCalls = Get-Content -Raw -LiteralPath $noPullLog
    Assert-True ($noPullCalls -match 'git fetch .* origin') 'no-pull did not refresh the validated origin.'
    Assert-True ($noPullCalls -notmatch 'git pull') 'no-pull modified the worktree.'

    $fetchFailureFixture = Initialize-Fixture -Name 'run-fetch-failure' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $fetchFailureFixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $fetchFailureFixture
    $fetchFailureLog = Join-Path $fetchFailureFixture 'calls.log'
    $fetchFailureEnvironment = Get-TestEnvironment -Fixture $fetchFailureFixture -LogPath $fetchFailureLog
    $fetchFailureEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'fetch-failure'
    $fetchFailure = Invoke-Batch -BatchPath (Join-Path $fetchFailureFixture 'Run.bat') -Arguments @('no-pause') -Environment $fetchFailureEnvironment
    Assert-ExitCode $fetchFailure 1 'Run default fetch failure'
    $fetchFailureCalls = Get-Content -Raw -LiteralPath $fetchFailureLog
    Assert-True ($fetchFailureCalls -notmatch 'rustup|powershell') 'Run built or elevated after a failed default fetch.'

    $statusFailureFixture = Initialize-Fixture -Name 'run-status-failure' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $statusFailureFixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $statusFailureFixture
    $statusFailureLog = Join-Path $statusFailureFixture 'calls.log'
    $statusFailureEnvironment = Get-TestEnvironment -Fixture $statusFailureFixture -LogPath $statusFailureLog
    $statusFailureEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'status-failure'
    $statusFailure = Invoke-Batch -BatchPath (Join-Path $statusFailureFixture 'Run.bat') -Arguments @('no-fetch', 'no-pause') -Environment $statusFailureEnvironment
    Assert-ExitCode $statusFailure 1 'Run Git status failure'
    $statusFailureCalls = Get-Content -Raw -LiteralPath $statusFailureLog
    Assert-True ($statusFailureCalls -notmatch 'rustup|powershell') 'Run built or elevated after Git status failed.'
    Assert-NoStatusTemporaryFile -Fixture $statusFailureFixture -Context 'Run status failure'

    $runCollisionFixture = Initialize-RunFixture -Name 'run-status-container-collision'
    $runCollisionLog = Join-Path $runCollisionFixture 'calls.log'
    $runCollisionBase = Join-Path $runCollisionFixture 'temp/winprofile-run-git-status-forced'
    $runCollisionContainer = "$runCollisionBase-1"
    $runCollisionSentinel = Join-Path $runCollisionContainer 'sentinel.txt'
    New-Item -ItemType Directory -Path $runCollisionContainer | Out-Null
    Write-AsciiFile -Path $runCollisionSentinel -Lines @('owned-by-other-instance')
    $runCollisionEnvironment = Get-TestEnvironment -Fixture $runCollisionFixture -LogPath $runCollisionLog
    $runCollisionEnvironment.WINPROFILE_TEST_STATUS_CONTAINER_BASE = $runCollisionBase
    $runCollision = Invoke-Batch -BatchPath (Join-Path $runCollisionFixture 'Run.bat') -Arguments @('no-fetch', 'no-pause') -Environment $runCollisionEnvironment
    Assert-ExitCode $runCollision 0 'Run atomic status container collision'
    Assert-True ((Get-Content -Raw -LiteralPath $runCollisionSentinel).Trim() -eq 'owned-by-other-instance') 'Run modified the colliding container owned by another instance.'
    Assert-True (-not (Test-Path -LiteralPath "$runCollisionBase-2")) 'Run left its acquired status container behind.'
    Remove-Item -LiteralPath $runCollisionSentinel -Force
    Remove-Item -LiteralPath $runCollisionContainer -Force
    Assert-NoStatusTemporaryFile -Fixture $runCollisionFixture -Context 'Run status collision'

    $runResidueFixture = Initialize-RunFixture -Name 'run-status-cleanup-failure'
    $runResidueLog = Join-Path $runResidueFixture 'calls.log'
    $runResidueBase = Join-Path $runResidueFixture 'temp/winprofile-run-git-status-forced'
    $runResidueContainer = "$runResidueBase-1"
    $runResidueFile = Join-Path $runResidueContainer 'blocker.txt'
    $runResidueEnvironment = Get-TestEnvironment -Fixture $runResidueFixture -LogPath $runResidueLog
    $runResidueEnvironment.WINPROFILE_TEST_STATUS_CONTAINER_BASE = $runResidueBase
    $runResidueEnvironment.WINPROFILE_TEST_STATUS_RESIDUE_FILE = $runResidueFile
    $runResidue = Invoke-Batch -BatchPath (Join-Path $runResidueFixture 'Run.bat') -Arguments @('no-fetch', 'no-pause') -Environment $runResidueEnvironment
    Assert-ExitCode $runResidue 1 'Run status cleanup failure'
    Assert-True (Test-Path -LiteralPath $runResidueFile -PathType Leaf) 'Run cleanup-failure oracle did not leave its injected residue.'
    Assert-True ((Get-Content -Raw -LiteralPath $runResidueLog) -notmatch 'rustup|powershell') 'Run continued after status cleanup failed.'
    Remove-Item -LiteralPath $runResidueFile -Force
    Remove-Item -LiteralPath $runResidueContainer -Force
    Assert-NoStatusTemporaryFile -Fixture $runResidueFixture -Context 'Run cleanup-failure oracle'

    $behindFixture = Initialize-RunFixture -Name 'run-default-behind'
    $behindLog = Join-Path $behindFixture 'calls.log'
    $behindEnvironment = Get-TestEnvironment -Fixture $behindFixture -LogPath $behindLog
    $behindEnvironment.WINPROFILE_TEST_GRAPH_SCENARIO = 'behind'
    $behindResult = Invoke-Batch -BatchPath (Join-Path $behindFixture 'Run.bat') -Arguments @('no-pause') -Environment $behindEnvironment
    Assert-ExitCode $behindResult 0 'Run default clean main behind'
    $behindCalls = Get-Content -Raw -LiteralPath $behindLog
    Assert-True ($behindCalls -match 'git fetch .* origin') 'Run default did not fetch the official origin.'
    Assert-True ($behindCalls -match 'git pull --ff-only --quiet origin "?main"?') 'Run default did not fast-forward a clean behind main.'
    Assert-NoStatusTemporaryFile -Fixture $behindFixture -Context 'Run default behind'

    foreach ($case in @('ahead', 'diverged', 'dirty')) {
        $fixture = Initialize-RunFixture -Name "run-explicit-pull-refused-$case"
        $log = Join-Path $fixture 'calls.log'
        $environment = Get-TestEnvironment -Fixture $fixture -LogPath $log
        if ($case -eq 'dirty') {
            $environment.WINPROFILE_TEST_GRAPH_SCENARIO = 'behind'
            $dirtyPath = Join-Path $fixture 'preexisting-dirty.flag'
            Write-AsciiFile -Path $dirtyPath -Lines @('dirty')
            $environment.WINPROFILE_TEST_DIRTY_FILE = $dirtyPath
        }
        else {
            $environment.WINPROFILE_TEST_GRAPH_SCENARIO = $case
        }
        $result = Invoke-Batch -BatchPath (Join-Path $fixture 'Run.bat') -Arguments @('pull', 'no-pause') -Environment $environment
        Assert-ExitCode $result 2 "Run explicit pull refused $case"
        $calls = Get-Content -Raw -LiteralPath $log
        Assert-True ($calls -notmatch 'git pull|rustup|powershell') "Run explicit pull continued for $case."
        Assert-NoStatusTemporaryFile -Fixture $fixture -Context "Run explicit pull $case"
    }

    foreach ($case in @('dirty-behind', 'ahead', 'diverged')) {
        $fixture = Initialize-RunFixture -Name "run-default-no-pull-$case"
        $log = Join-Path $fixture 'calls.log'
        $environment = Get-TestEnvironment -Fixture $fixture -LogPath $log
        if ($case -eq 'dirty-behind') {
            $environment.WINPROFILE_TEST_GRAPH_SCENARIO = 'behind'
            $dirtyPath = Join-Path $fixture 'preexisting-dirty.flag'
            Write-AsciiFile -Path $dirtyPath -Lines @('dirty')
            $environment.WINPROFILE_TEST_DIRTY_FILE = $dirtyPath
        }
        else {
            $environment.WINPROFILE_TEST_GRAPH_SCENARIO = $case
        }
        $result = Invoke-Batch -BatchPath (Join-Path $fixture 'Run.bat') -Arguments @('no-pause') -Environment $environment
        Assert-ExitCode $result 0 "Run default without unsafe pull $case"
        $calls = Get-Content -Raw -LiteralPath $log
        Assert-True ($calls -notmatch 'git pull') "Run default pulled an unsafe $case worktree."
        Assert-True ($calls -match 'rustup .* cargo "?build"?') "Run default did not continue with the local $case worktree."
        Assert-NoStatusTemporaryFile -Fixture $fixture -Context "Run default $case"
    }

    $pullFixture = Initialize-Fixture -Name 'run-explicit-pull-clean' -GitWorktree
    foreach ($relative in @('Run.bat', 'scripts/Cargo.bat')) {
        Copy-ProductScript -Fixture $pullFixture -RelativePath $relative
    }
    Write-ToolStub -Fixture $pullFixture
    $pullLog = Join-Path $pullFixture 'calls.log'
    $pullEnvironment = Get-TestEnvironment -Fixture $pullFixture -LogPath $pullLog
    $pullResult = Invoke-Batch -BatchPath (Join-Path $pullFixture 'Run.bat') -Arguments @('pull', 'clean', 'no-pause') -Environment $pullEnvironment
    Assert-ExitCode $pullResult 0 'Run pull/clean/no-pause'
    $pullCalls = Get-Content -Raw -LiteralPath $pullLog
    Assert-True ($pullCalls -match 'git pull --ff-only --quiet origin "?main"?') 'Run did not pull from the explicit origin and branch.'
    Assert-True ($pullCalls -match 'cargo "?clean"? -p app-ui') 'Run clean did not use the pinned Cargo wrapper.'

    function Initialize-ReleaseFixture {
        param([string]$Name)
        $fixture = Initialize-Fixture -Name $Name -GitWorktree
        Copy-ProductScript -Fixture $fixture -RelativePath 'Release.bat'
        Write-ToolStub -Fixture $fixture
        Write-QualityStub -Fixture $fixture
        Write-ApprovalMarker -Fixture $fixture
        return $fixture
    }

    $releaseArgsFixture = Initialize-Fixture -Name 'release-args'
    Copy-ProductScript -Fixture $releaseArgsFixture -RelativePath 'Release.bat'
    $releaseUnknown = Invoke-Batch -BatchPath (Join-Path $releaseArgsFixture 'Release.bat') -Arguments @('typo', 'no-pause')
    Assert-ExitCode $releaseUnknown 2 'Release unknown argument'
    Assert-True ($releaseUnknown.Output -notmatch 'Appuyez|Press any key') 'Release ignored no-pause after an unknown argument.'

    $missingNotesFixture = Initialize-ReleaseFixture -Name 'release-missing-notes'
    Remove-Item -LiteralPath (Join-Path $missingNotesFixture 'docs/release-v2026.819.0.md') -Force
    $missingNotesLog = Join-Path $missingNotesFixture 'calls.log'
    $missingNotesEnvironment = Get-TestEnvironment -Fixture $missingNotesFixture -LogPath $missingNotesLog
    $missingNotes = Invoke-Batch -BatchPath (Join-Path $missingNotesFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $missingNotesEnvironment
    Assert-ExitCode $missingNotes 1 'Release missing notes'
    Assert-True (-not (Test-Path -LiteralPath $missingNotesLog)) 'Release contacted tools before validating release notes.'

    $releaseFixture = Initialize-ReleaseFixture -Name 'release-valid'
    $releaseLog = Join-Path $releaseFixture 'calls.log'
    $releaseEnvironment = Get-TestEnvironment -Fixture $releaseFixture -LogPath $releaseLog
    $releaseCheck = Invoke-Batch -BatchPath (Join-Path $releaseFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $releaseEnvironment
    Assert-ExitCode $releaseCheck 0 'Release exact-marker check'
    $releaseCalls = Get-Content -Raw -LiteralPath $releaseLog
    Assert-True ($releaseCalls -notmatch 'git (tag|push)') 'Release check created or pushed a tag.'

    foreach ($case in @('wrong-sha', 'extra-line', 'blank-line', 'duplicate-line', 'reordered')) {
        $fixture = Initialize-ReleaseFixture -Name "release-marker-$case"
        switch ($case) {
            'wrong-sha' { Write-ApprovalMarker -Fixture $fixture -Commit $otherSha }
            'extra-line' { Write-ApprovalMarker -Fixture $fixture -AdditionalLines @('extra=forbidden') }
            'blank-line' { Write-ApprovalMarker -Fixture $fixture -AdditionalLines @('') }
            'duplicate-line' { Write-ApprovalMarker -Fixture $fixture -AdditionalLines @('result=approved') }
            'reordered' {
                Write-AsciiFile -Path (Join-Path $fixture 'work-private-docs/release-v2026.819.0.approved') -Lines @(
                    'WINPROFILE_RELEASE_VM_APPROVAL_V1',
                    "commit=$headSha",
                    'tag=v2026.819.0',
                    'result=approved'
                )
            }
        }
        $log = Join-Path $fixture 'calls.log'
        $environment = Get-TestEnvironment -Fixture $fixture -LogPath $log
        $result = Invoke-Batch -BatchPath (Join-Path $fixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $environment
        Assert-ExitCode $result 1 "Release marker $case"
        $calls = Get-Content -Raw -LiteralPath $log
        Assert-True ($calls -notmatch 'gh |git (tag|push)') "Release marker $case reached credentials or tag operations."
    }

    $secretFixture = Initialize-ReleaseFixture -Name 'release-secret-prefix'
    $secretLog = Join-Path $secretFixture 'calls.log'
    $secretEnvironment = Get-TestEnvironment -Fixture $secretFixture -LogPath $secretLog
    $secretEnvironment.WINPROFILE_TEST_GH_SCENARIO = 'prefix-only'
    $secretResult = Invoke-Batch -BatchPath (Join-Path $secretFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $secretEnvironment
    Assert-ExitCode $secretResult 1 'Release secret exact equality'

    $originFixture = Initialize-ReleaseFixture -Name 'release-hostile-origin'
    $originLog = Join-Path $originFixture 'calls.log'
    $originEnvironment = Get-TestEnvironment -Fixture $originFixture -LogPath $originLog
    $originEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'hostile-origin'
    $originResult = Invoke-Batch -BatchPath (Join-Path $originFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $originEnvironment
    Assert-ExitCode $originResult 1 'Release hostile origin'
    $originCalls = Get-Content -Raw -LiteralPath $originLog
    Assert-True ($originCalls -notmatch 'git fetch|gh |git (tag|push)') 'Release used network or tag operations after a hostile origin.'

    $hostilePushFixture = Initialize-ReleaseFixture -Name 'release-hostile-push'
    $hostilePushLog = Join-Path $hostilePushFixture 'calls.log'
    $hostilePushEnvironment = Get-TestEnvironment -Fixture $hostilePushFixture -LogPath $hostilePushLog
    $hostilePushEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'hostile-push'
    $hostilePush = Invoke-Batch -BatchPath (Join-Path $hostilePushFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $hostilePushEnvironment
    Assert-ExitCode $hostilePush 1 'Release hostile push URL'
    $hostilePushCalls = Get-Content -Raw -LiteralPath $hostilePushLog
    Assert-True (([regex]::Matches($hostilePushCalls, 'git remote get-url')).Count -eq 2) 'Release did not inspect fetch and push URLs independently.'
    Assert-True ($hostilePushCalls -notmatch 'git (fetch|ls-remote|tag|push)|gh ') 'Release continued after rejecting a hostile push URL.'

    $duplicateOriginFixture = Initialize-ReleaseFixture -Name 'release-duplicate-origin'
    $duplicateOriginLog = Join-Path $duplicateOriginFixture 'calls.log'
    $duplicateOriginEnvironment = Get-TestEnvironment -Fixture $duplicateOriginFixture -LogPath $duplicateOriginLog
    $duplicateOriginEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'duplicate-origin'
    $duplicateOrigin = Invoke-Batch -BatchPath (Join-Path $duplicateOriginFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $duplicateOriginEnvironment
    Assert-ExitCode $duplicateOrigin 1 'Release duplicate origin URLs'
    $duplicateOriginCalls = Get-Content -Raw -LiteralPath $duplicateOriginLog
    Assert-True ($duplicateOriginCalls -notmatch 'git fetch|gh |git (tag|push)') 'Release accepted ambiguous origin URLs.'

    $releaseStatusFailureFixture = Initialize-ReleaseFixture -Name 'release-status-failure'
    $releaseStatusFailureLog = Join-Path $releaseStatusFailureFixture 'calls.log'
    $releaseStatusFailureEnvironment = Get-TestEnvironment -Fixture $releaseStatusFailureFixture -LogPath $releaseStatusFailureLog
    $releaseStatusFailureEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'status-failure'
    $releaseStatusFailure = Invoke-Batch -BatchPath (Join-Path $releaseStatusFailureFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $releaseStatusFailureEnvironment
    Assert-ExitCode $releaseStatusFailure 1 'Release Git status failure'
    $releaseStatusFailureCalls = Get-Content -Raw -LiteralPath $releaseStatusFailureLog
    Assert-True ($releaseStatusFailureCalls -notmatch 'git (fetch|ls-remote|tag|push)|gh |quality') 'Release continued after Git status failed.'
    Assert-NoStatusTemporaryFile -Fixture $releaseStatusFailureFixture -Context 'Release status failure'

    $releaseCollisionFixture = Initialize-ReleaseFixture -Name 'release-status-container-collision'
    $releaseCollisionLog = Join-Path $releaseCollisionFixture 'calls.log'
    $releaseCollisionBase = Join-Path $releaseCollisionFixture 'temp/winprofile-release-git-status-forced'
    $releaseCollisionContainer = "$releaseCollisionBase-1"
    $releaseCollisionSentinel = Join-Path $releaseCollisionContainer 'sentinel.txt'
    New-Item -ItemType Directory -Path $releaseCollisionContainer | Out-Null
    Write-AsciiFile -Path $releaseCollisionSentinel -Lines @('owned-by-other-instance')
    $releaseCollisionEnvironment = Get-TestEnvironment -Fixture $releaseCollisionFixture -LogPath $releaseCollisionLog
    $releaseCollisionEnvironment.WINPROFILE_TEST_STATUS_CONTAINER_BASE = $releaseCollisionBase
    $releaseCollision = Invoke-Batch -BatchPath (Join-Path $releaseCollisionFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $releaseCollisionEnvironment
    Assert-ExitCode $releaseCollision 0 'Release atomic status container collision'
    Assert-True ((Get-Content -Raw -LiteralPath $releaseCollisionSentinel).Trim() -eq 'owned-by-other-instance') 'Release modified the colliding container owned by another instance.'
    Assert-True (-not (Test-Path -LiteralPath "$releaseCollisionBase-2")) 'Release left its acquired status container behind.'
    Remove-Item -LiteralPath $releaseCollisionSentinel -Force
    Remove-Item -LiteralPath $releaseCollisionContainer -Force
    Assert-NoStatusTemporaryFile -Fixture $releaseCollisionFixture -Context 'Release status collision'

    $releaseResidueFixture = Initialize-ReleaseFixture -Name 'release-status-cleanup-failure'
    $releaseResidueLog = Join-Path $releaseResidueFixture 'calls.log'
    $releaseResidueBase = Join-Path $releaseResidueFixture 'temp/winprofile-release-git-status-forced'
    $releaseResidueContainer = "$releaseResidueBase-1"
    $releaseResidueFile = Join-Path $releaseResidueContainer 'blocker.txt'
    $releaseResidueEnvironment = Get-TestEnvironment -Fixture $releaseResidueFixture -LogPath $releaseResidueLog
    $releaseResidueEnvironment.WINPROFILE_TEST_STATUS_CONTAINER_BASE = $releaseResidueBase
    $releaseResidueEnvironment.WINPROFILE_TEST_STATUS_RESIDUE_FILE = $releaseResidueFile
    $releaseResidue = Invoke-Batch -BatchPath (Join-Path $releaseResidueFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $releaseResidueEnvironment
    Assert-ExitCode $releaseResidue 1 'Release status cleanup failure'
    Assert-True (Test-Path -LiteralPath $releaseResidueFile -PathType Leaf) 'Release cleanup-failure oracle did not leave its injected residue.'
    $releaseResidueCalls = Get-Content -Raw -LiteralPath $releaseResidueLog
    Assert-True ($releaseResidueCalls -notmatch 'git (fetch|ls-remote|tag|push)|gh |quality') 'Release continued after status cleanup failed.'
    Remove-Item -LiteralPath $releaseResidueFile -Force
    Remove-Item -LiteralPath $releaseResidueContainer -Force
    Assert-NoStatusTemporaryFile -Fixture $releaseResidueFixture -Context 'Release cleanup-failure oracle'

    $secondStatusFailureFixture = Initialize-ReleaseFixture -Name 'release-second-status-failure'
    $secondStatusFailureLog = Join-Path $secondStatusFailureFixture 'calls.log'
    $secondStatusFailureCount = Join-Path $secondStatusFailureFixture 'status-count.txt'
    $secondStatusFailureEnvironment = Get-TestEnvironment -Fixture $secondStatusFailureFixture -LogPath $secondStatusFailureLog
    $secondStatusFailureEnvironment.WINPROFILE_TEST_GIT_SCENARIO = 'second-status-failure'
    $secondStatusFailureEnvironment.WINPROFILE_TEST_STATUS_COUNT_FILE = $secondStatusFailureCount
    $secondStatusFailure = Invoke-Batch -BatchPath (Join-Path $secondStatusFailureFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $secondStatusFailureEnvironment
    Assert-ExitCode $secondStatusFailure 1 'Release second Git status failure'
    $secondStatusFailureCalls = Get-Content -Raw -LiteralPath $secondStatusFailureLog
    Assert-True ($secondStatusFailureCalls -match 'quality no-pause') 'Release did not reach final clean-tree revalidation.'
    Assert-True ($secondStatusFailureCalls -notmatch 'git (tag|push)') 'Release tagged after final Git status failed.'
    Assert-NoStatusTemporaryFile -Fixture $secondStatusFailureFixture -Context 'Release second status failure'

    $raceFixture = Initialize-ReleaseFixture -Name 'release-head-race'
    $raceLog = Join-Path $raceFixture 'calls.log'
    $raceFile = Join-Path $raceFixture 'head-raced.flag'
    $raceEnvironment = Get-TestEnvironment -Fixture $raceFixture -LogPath $raceLog
    $raceEnvironment.WINPROFILE_TEST_RACE_FILE = $raceFile
    $raceResult = Invoke-Batch -BatchPath (Join-Path $raceFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $raceEnvironment
    Assert-ExitCode $raceResult 1 'Release HEAD race'
    Assert-True ((Get-Content -Raw -LiteralPath $raceLog) -notmatch 'git (tag|push)') 'Release tagged after HEAD changed.'

    $tamperFixture = Initialize-ReleaseFixture -Name 'release-marker-race'
    $tamperLog = Join-Path $tamperFixture 'calls.log'
    $tamperMarker = Join-Path $tamperFixture 'work-private-docs/release-v2026.819.0.approved'
    $tamperEnvironment = Get-TestEnvironment -Fixture $tamperFixture -LogPath $tamperLog
    $tamperEnvironment.WINPROFILE_TEST_TAMPER_MARKER = $tamperMarker
    $tamperResult = Invoke-Batch -BatchPath (Join-Path $tamperFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $tamperEnvironment
    Assert-ExitCode $tamperResult 1 'Release marker race'
    Assert-True ((Get-Content -Raw -LiteralPath $tamperLog) -notmatch 'git (tag|push)') 'Release tagged after marker changed.'

    $dirtyFixture = Initialize-ReleaseFixture -Name 'release-dirty-race'
    $dirtyLog = Join-Path $dirtyFixture 'calls.log'
    $dirtyFile = Join-Path $dirtyFixture 'dirty-after-quality.flag'
    $dirtyEnvironment = Get-TestEnvironment -Fixture $dirtyFixture -LogPath $dirtyLog
    $dirtyEnvironment.WINPROFILE_TEST_DIRTY_FILE = $dirtyFile
    $dirtyResult = Invoke-Batch -BatchPath (Join-Path $dirtyFixture 'Release.bat') -Arguments @('check', 'no-pause') -Environment $dirtyEnvironment
    Assert-ExitCode $dirtyResult 1 'Release dirty-tree race'
    Assert-True ((Get-Content -Raw -LiteralPath $dirtyLog) -notmatch 'git (tag|push)') 'Release tagged after the quality gates dirtied the tree.'

    $publishFixture = Initialize-ReleaseFixture -Name 'release-publish-stubbed'
    $publishLog = Join-Path $publishFixture 'calls.log'
    $publishEnvironment = Get-TestEnvironment -Fixture $publishFixture -LogPath $publishLog
    $publishResult = Invoke-Batch -BatchPath (Join-Path $publishFixture 'Release.bat') -Arguments @('no-pause') -Environment $publishEnvironment -InputText 'v2026.819.0'
    Assert-ExitCode $publishResult 0 'Release stubbed publish'
    $publishCalls = Get-Content -Raw -LiteralPath $publishLog
    $tagPattern = 'git tag -a "?v2026\.819\.0"? "?{0}"? -m "?WinProfile 2026\.819\.0"?' -f [regex]::Escape($headSha)
    Assert-True ($publishCalls -match $tagPattern) "Release did not bind the annotated tag to the captured HEAD SHA.`n$publishCalls"
    Assert-True ($publishCalls -match 'git push origin "?v2026\.819\.0"?') 'Release did not push only the explicit version tag.'

    $runSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'Run.bat')
    Assert-True ($runSource -notmatch 'ExecutionPolicy\s+Bypass') 'Run contains the forbidden execution-policy bypass.'
    $releaseSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'Release.bat')
    Assert-True ($releaseSource -match 'tag -a "!TAG!" "!HEAD_SHA!"') 'Release source does not explicitly tag the captured HEAD SHA.'

    $testSource = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'Test.bat')
    Assert-True ($testSource -match 'set "SLINT_EMIT_DEBUG_INFO=1"') 'Test does not enable the critical Slint metadata before workspace tests.'
    Assert-True ($testSource -match 'Test-BatchContracts\.ps1') 'Test does not execute this batch-contract harness.'

    foreach ($workflowName in @('ci.yml', 'release.yml')) {
        $workflow = Get-Content -Raw -LiteralPath (Join-Path $repoRoot ".github/workflows/$workflowName")
        Assert-True ($workflow -match '\.\\scripts\\Test-BatchContracts\.ps1') "$workflowName does not execute the batch-contract harness."
        $metadataCount = ([regex]::Matches($workflow, 'SLINT_EMIT_DEBUG_INFO:')).Count
        Assert-True ($metadataCount -eq 1) "$workflowName must scope Slint metadata to exactly one step."
        $testStepPattern = '(?ms)- name: Tests\s+shell: pwsh\s+env:\s+SLINT_EMIT_DEBUG_INFO: "1"\s+run: cargo'
        Assert-True ($workflow -match $testStepPattern) "$workflowName does not scope Slint metadata to the Tests step."
    }

    Write-Output 'Batch contract tests passed.'
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        $resolvedTempRoot = [IO.Path]::GetFullPath($tempRoot)
        $expectedPrefix = [IO.Path]::GetFullPath((Join-Path $tempParent 'winprofile-batch-contracts-'))
        if (-not $resolvedTempRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove an unexpected batch-contract fixture path: $resolvedTempRoot"
        }
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

exit 0
