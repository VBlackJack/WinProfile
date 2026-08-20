@echo off
REM Copyright 2026 Julien Bombled
REM Licensed under the Apache License, Version 2.0.
REM
REM Runs Cargo through the exact Windows GNU toolchain used by local gates.

setlocal
set "WINPROFILE_TOOLCHAIN=1.97.1-x86_64-pc-windows-gnu"
set "RUSTUP_EXE="
for %%I in ("%~dp0..\target") do set "CARGO_TARGET_DIR=%%~fI"

if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" if defined WINPROFILE_TEST_RUSTUP set "RUSTUP_EXE=%WINPROFILE_TEST_RUSTUP%"

if not defined RUSTUP_EXE (
    where rustup.exe >nul 2>&1
    if not errorlevel 1 set "RUSTUP_EXE=rustup.exe"
)

if not defined RUSTUP_EXE if exist "%USERPROFILE%\.cargo\bin\rustup.exe" set "RUSTUP_EXE=%USERPROFILE%\.cargo\bin\rustup.exe"

if not defined RUSTUP_EXE (
    echo ERROR: rustup was not found.
    echo Install Rust with rustup, then run this command again.
    endlocal & exit /b 9009
)

call "%RUSTUP_EXE%" toolchain list | findstr /b /c:"%WINPROFILE_TOOLCHAIN%" >nul
if not errorlevel 1 goto :run

echo Installing pinned Rust toolchain %WINPROFILE_TOOLCHAIN%...
call "%RUSTUP_EXE%" toolchain install "%WINPROFILE_TOOLCHAIN%" --profile minimal --component clippy,rustfmt
if errorlevel 1 (
    echo ERROR: the pinned Rust toolchain could not be installed.
    endlocal & exit /b 1
)

:run
call "%RUSTUP_EXE%" run "%WINPROFILE_TOOLCHAIN%" cargo %*
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%
