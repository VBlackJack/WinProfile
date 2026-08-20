@echo off
REM Copyright 2026 Julien Bombled
REM Licensed under the Apache License, Version 2.0.
REM
REM WinProfile local quality gates.
REM Usage: Test.bat [no-pause]

setlocal
cd /d "%~dp0"
title WinProfile - Tests

set "NO_PAUSE="
set "ARGUMENT_ERROR="
:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="no-pause" (set "NO_PAUSE=1" & shift & goto :parse_args)
echo Unknown option: %~1
set "ARGUMENT_ERROR=1"
shift
goto :parse_args

:args_done
set "DOUBLE_CLICK="
echo %CMDCMDLINE% | find /i "/c" >nul && set "DOUBLE_CLICK=1"
if defined ARGUMENT_ERROR (
    echo Usage: Test.bat [no-pause]
    set "EXIT_CODE=2"
    goto :finish
)

set "SLINT_EMIT_DEBUG_INFO="
set "POWERSHELL_EXE="
if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" if defined WINPROFILE_TEST_POWERSHELL set "POWERSHELL_EXE=%WINPROFILE_TEST_POWERSHELL%"
if not defined POWERSHELL_EXE (
    where pwsh.exe >nul 2>&1
    if not errorlevel 1 set "POWERSHELL_EXE=pwsh.exe"
    if not defined POWERSHELL_EXE (
        where powershell.exe >nul 2>&1
        if not errorlevel 1 set "POWERSHELL_EXE=powershell.exe"
    )
)
if not defined POWERSHELL_EXE (
    echo ERROR: PowerShell was not found.
    set "EXIT_CODE=9009"
    goto :finish
)

echo [1/4] Batch contract tests...
call "%POWERSHELL_EXE%" -NoProfile -File "%~dp0scripts\Test-BatchContracts.ps1"
if errorlevel 1 goto :failed

echo.
echo [2/4] Formatting...
call "%~dp0scripts\Cargo.bat" fmt --all -- --check
if errorlevel 1 goto :failed

echo.
echo [3/4] Clippy...
call "%~dp0scripts\Cargo.bat" clippy --workspace --all-targets --all-features --locked -- -D warnings
if errorlevel 1 goto :failed

echo.
echo [4/4] Tests with critical Slint accessibility metadata...
set "SLINT_EMIT_DEBUG_INFO=1"
call "%~dp0scripts\Cargo.bat" test --workspace --all-features --locked
if errorlevel 1 goto :failed

echo.
echo All local quality gates passed.
set "EXIT_CODE=0"
goto :finish

:failed
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" set "EXIT_CODE=1"
echo.
echo Quality gates FAILED with exit code %EXIT_CODE%.

:finish
if defined DOUBLE_CLICK if not defined NO_PAUSE pause
endlocal & exit /b %EXIT_CODE%
