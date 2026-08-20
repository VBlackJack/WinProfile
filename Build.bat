@echo off
REM Copyright 2026 Julien Bombled
REM Licensed under the Apache License, Version 2.0.
REM
REM WinProfile debug build.

setlocal
cd /d "%~dp0"
title WinProfile - Build

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
    echo Usage: Build.bat [no-pause]
    set "EXIT_CODE=2"
    goto :finish
)

echo Building WinProfile with the pinned Windows GNU toolchain...
call "%~dp0scripts\Cargo.bat" build -p app-ui --locked
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if "%EXIT_CODE%"=="0" (
    if not exist "%~dp0target\debug\winprofile-admin.exe" (
        echo Build FAILED: target\debug\winprofile-admin.exe was not produced.
        set "EXIT_CODE=1"
    ) else (
        echo Build passed.
        echo Executable: target\debug\winprofile-admin.exe
    )
) else (
    echo Build FAILED with exit code %EXIT_CODE%.
)

:finish
if defined DOUBLE_CLICK if not defined NO_PAUSE pause
endlocal & exit /b %EXIT_CODE%
