@echo off
REM Copyright 2026 Julien Bombled
REM Licensed under the Apache License, Version 2.0.
REM
REM WinProfile quick launch.
REM
REM Safe update rules:
REM   - default fetch failures are fatal;
REM   - only main is pulled automatically;
REM   - no-fetch performs no Git network operation and implies no pull;
REM   - no-pull may fetch but never modifies the worktree;
REM   - only the official WinProfile origin is contacted.
REM
REM Usage:
REM   Run.bat [pull^|no-pull] [no-fetch] [clean] [no-pause]

setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title WinProfile - Run

set "DOUBLE_CLICK="
echo %CMDCMDLINE% | find /i "/c" >nul && set "DOUBLE_CLICK=1"

set "CLEAN="
set "FORCE_PULL="
set "NO_PULL="
set "NO_FETCH="
set "NO_PAUSE="
set "ARGUMENT_ERROR="

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="clean"    (set "CLEAN=1"      & shift & goto :parse_args)
if /i "%~1"=="pull"     (set "FORCE_PULL=1" & shift & goto :parse_args)
if /i "%~1"=="no-pull"  (set "NO_PULL=1"    & shift & goto :parse_args)
if /i "%~1"=="no-fetch" (set "NO_FETCH=1"   & shift & goto :parse_args)
if /i "%~1"=="no-pause" (set "NO_PAUSE=1"   & shift & goto :parse_args)
echo Unknown option: %~1
set "ARGUMENT_ERROR=1"
shift
goto :parse_args

:args_done
if defined ARGUMENT_ERROR (
    echo Usage: Run.bat [pull^|no-pull] [no-fetch] [clean] [no-pause]
    set "EXIT_CODE=2"
    goto :finish
)
if defined FORCE_PULL if defined NO_PULL (
    echo ERROR: pull and no-pull cannot be combined.
    set "EXIT_CODE=2"
    goto :finish
)
if defined FORCE_PULL if defined NO_FETCH (
    echo ERROR: pull and no-fetch cannot be combined.
    set "EXIT_CODE=2"
    goto :finish
)
if defined NO_FETCH set "NO_PULL=1"

set "GIT_COMMAND=git"
if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" if defined WINPROFILE_TEST_GIT set "GIT_COMMAND=%WINPROFILE_TEST_GIT%"
if not exist "%~dp0.git" goto :source_archive

if /i not "%WINPROFILE_BATCH_TEST_MODE%"=="1" (
    where git.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: git.exe was not found for this Git worktree.
        set "EXIT_CODE=9009"
        goto :finish
    )
)
call "!GIT_COMMAND!" rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo ERROR: the repository metadata could not be read.
    set "EXIT_CODE=1"
    goto :finish
)

set "BRANCH="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse --abbrev-ref HEAD 2^>nul') do set "BRANCH=%%A"
if not defined BRANCH (
    echo ERROR: the current Git branch could not be determined.
    set "EXIT_CODE=1"
    goto :finish
)

if not defined NO_FETCH (
    call :validate_origin
    if errorlevel 1 (
        set "EXIT_CODE=1"
        goto :finish
    )
    echo Checking origin/!BRANCH!...
    call "!GIT_COMMAND!" fetch --quiet --no-tags origin "+refs/heads/!BRANCH!:refs/remotes/origin/!BRANCH!"
    if errorlevel 1 (
        echo ERROR: origin/!BRANCH! could not be fetched. Use no-fetch to skip Git network access.
        set "EXIT_CODE=1"
        goto :finish
    )
)

set "SHA="
set "SUBJECT="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse --short HEAD 2^>nul') do set "SHA=%%A"
for /f "delims=" %%A in ('call "!GIT_COMMAND!" log -1 --format^=%%s 2^>nul') do set "SUBJECT=%%A"
if not defined SHA (
    echo ERROR: the current commit could not be determined.
    set "EXIT_CODE=1"
    goto :finish
)

call :measure_clean_tree
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)

set "BEHIND=unknown"
set "AHEAD=unknown"
call "!GIT_COMMAND!" show-ref --verify --quiet "refs/remotes/origin/!BRANCH!"
if not errorlevel 1 (
    set "BEHIND="
    set "AHEAD="
    for /f %%A in ('call "!GIT_COMMAND!" rev-list --count "HEAD..origin/!BRANCH!" 2^>nul') do set "BEHIND=%%A"
    for /f %%A in ('call "!GIT_COMMAND!" rev-list --count "origin/!BRANCH!..HEAD" 2^>nul') do set "AHEAD=%%A"
    if not defined BEHIND (
        echo ERROR: the behind count could not be determined.
        set "EXIT_CODE=1"
        goto :finish
    )
    if not defined AHEAD (
        echo ERROR: the ahead count could not be determined.
        set "EXIT_CODE=1"
        goto :finish
    )
)

set "DO_PULL="
if defined FORCE_PULL (
    if not "!DIRTY!"=="0" goto :unsafe_pull
    if /i "!AHEAD!"=="unknown" goto :unsafe_pull
    if not "!AHEAD!"=="0" goto :unsafe_pull
    set "DO_PULL=1"
)
if not defined NO_PULL if not defined FORCE_PULL if /i "!BRANCH!"=="main" if not "!BEHIND!"=="unknown" if not "!BEHIND!"=="0" if "!AHEAD!"=="0" if "!DIRTY!"=="0" set "DO_PULL=1"

if defined DO_PULL (
    call :validate_origin
    if errorlevel 1 (
        set "EXIT_CODE=1"
        goto :finish
    )
    echo Updating from origin/!BRANCH! with fast-forward only...
    call "!GIT_COMMAND!" pull --ff-only --quiet origin "!BRANCH!"
    if errorlevel 1 (
        echo ERROR: the fast-forward pull failed.
        set "EXIT_CODE=1"
        goto :finish
    )
    for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse --short HEAD 2^>nul') do set "SHA=%%A"
    for /f "delims=" %%A in ('call "!GIT_COMMAND!" log -1 --format^=%%s 2^>nul') do set "SUBJECT=%%A"
    set "BEHIND=0"
)

echo ----------------------------------------------------------------
echo  WinProfile - Quick launch
echo  Branch: !BRANCH! @ !SHA!
if defined SUBJECT echo  Last:   !SUBJECT!
if /i "!BEHIND!"=="unknown" (
    echo  Remote:  not inspected ^(Git offline mode^)
) else (
    if not "!BEHIND!"=="0" echo  WARN:   !BEHIND! commit^(s^) behind origin/!BRANCH!
    if not "!AHEAD!"=="0" echo  Info:   !AHEAD! commit^(s^) ahead of origin/!BRANCH!
)
if not "!DIRTY!"=="0" echo  Dirty:  !DIRTY! path^(s^) with uncommitted changes
echo ----------------------------------------------------------------
echo.
goto :build

:source_archive
if defined FORCE_PULL (
    echo ERROR: pull requires a Git worktree; this appears to be a source archive.
    set "EXIT_CODE=2"
    goto :finish
)
echo Source archive detected: no Git fetch or pull will run.
echo Rustup or Cargo may still download a missing toolchain or dependency.
echo.
goto :build

:unsafe_pull
echo ERROR: pull was refused because the worktree is dirty, the remote state is unknown, or local commits are present.
set "EXIT_CODE=2"
goto :finish

:measure_clean_tree
set "STATUS_FILE="
set "STATUS_CONTAINER="
set "STATUS_ROOT="
if not defined TEMP (
    echo ERROR: the temporary directory is not defined; the Git worktree state cannot be measured.
    exit /b 1
)
for %%I in ("!TEMP!") do set "STATUS_ROOT=%%~fI"
if not exist "!STATUS_ROOT!\." (
    echo ERROR: the temporary directory is unavailable; the Git worktree state cannot be measured.
    exit /b 1
)
set "STATUS_ATTEMPTS=0"

:choose_status_file
set /a STATUS_ATTEMPTS+=1
if !STATUS_ATTEMPTS! GTR 32 (
    echo ERROR: a unique temporary Git status container could not be allocated.
    exit /b 1
)
set "STATUS_CONTAINER="
if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" if defined WINPROFILE_TEST_STATUS_CONTAINER_BASE set "STATUS_CONTAINER=!WINPROFILE_TEST_STATUS_CONTAINER_BASE!-!STATUS_ATTEMPTS!"
if not defined STATUS_CONTAINER set "STATUS_CONTAINER=!STATUS_ROOT!\winprofile-run-git-status-!RANDOM!-!RANDOM!"
md "!STATUS_CONTAINER!" >nul 2>&1
if errorlevel 1 goto :choose_status_file
set "STATUS_FILE=!STATUS_CONTAINER!\status.txt"

call "!GIT_COMMAND!" status --porcelain >"!STATUS_FILE!" 2>nul
set "STATUS_RESULT=!ERRORLEVEL!"
set "DIRTY=0"
if "!STATUS_RESULT!"=="0" (
    for /f "usebackq delims=" %%A in ("!STATUS_FILE!") do set /a DIRTY+=1
)
call :cleanup_status_file
set "CLEANUP_RESULT=!ERRORLEVEL!"
if not "!STATUS_RESULT!"=="0" (
    echo ERROR: the Git worktree state could not be inspected.
)
if not "!CLEANUP_RESULT!"=="0" (
    echo ERROR: the temporary Git status file could not be removed.
)
if not "!STATUS_RESULT!"=="0" exit /b 1
if not "!CLEANUP_RESULT!"=="0" exit /b 1
exit /b 0

:cleanup_status_file
set "CLEANUP_FAILED=0"
if defined STATUS_FILE if exist "!STATUS_FILE!" (
    del /f /q "!STATUS_FILE!" >nul 2>&1
    if exist "!STATUS_FILE!" set "CLEANUP_FAILED=1"
)
if defined STATUS_CONTAINER if exist "!STATUS_CONTAINER!\." (
    rd "!STATUS_CONTAINER!" >nul 2>&1
    if exist "!STATUS_CONTAINER!\." set "CLEANUP_FAILED=1"
)
if "!CLEANUP_FAILED!"=="0" (
    set "STATUS_FILE="
    set "STATUS_CONTAINER="
    exit /b 0
)
exit /b 1

:build
if defined CLEAN (
    echo Cleaning app-ui build outputs...
    call "%~dp0scripts\Cargo.bat" clean -p app-ui
    if errorlevel 1 (
        set "EXIT_CODE=!ERRORLEVEL!"
        goto :finish
    )
    echo.
)

echo Building WinProfile...
call "%~dp0scripts\Cargo.bat" build -p app-ui --locked
if errorlevel 1 (
    set "EXIT_CODE=!ERRORLEVEL!"
    goto :finish
)

set "WINPROFILE_APP=%~dp0target\debug\winprofile-admin.exe"
if not exist "!WINPROFILE_APP!" (
    echo ERROR: built executable was not found at !WINPROFILE_APP!.
    set "EXIT_CODE=1"
    goto :finish
)

set "POWERSHELL_COMMAND=powershell.exe"
if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" if defined WINPROFILE_TEST_POWERSHELL set "POWERSHELL_COMMAND=%WINPROFILE_TEST_POWERSHELL%"
if /i not "%WINPROFILE_BATCH_TEST_MODE%"=="1" (
    where powershell.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: powershell.exe was not found.
        set "EXIT_CODE=9009"
        goto :finish
    )
)

echo Requesting administrator elevation...
call "!POWERSHELL_COMMAND!" -NoProfile -Command "Start-Process -FilePath $env:WINPROFILE_APP -Verb RunAs"
set "EXIT_CODE=!ERRORLEVEL!"
if not "!EXIT_CODE!"=="0" echo Launch FAILED with exit code !EXIT_CODE!.
goto :finish

:validate_origin
set "FETCH_URL_COUNT=0"
set "PUSH_URL_COUNT=0"
for /f "delims=" %%U in ('call "!GIT_COMMAND!" remote get-url --all origin 2^>nul') do (
    set /a FETCH_URL_COUNT+=1
    call :is_official_origin "%%U"
    if errorlevel 1 (
        echo ERROR: origin fetch URL is not an official WinProfile URL: %%U
        exit /b 1
    )
)
for /f "delims=" %%U in ('call "!GIT_COMMAND!" remote get-url --push --all origin 2^>nul') do (
    set /a PUSH_URL_COUNT+=1
    call :is_official_origin "%%U"
    if errorlevel 1 (
        echo ERROR: origin push URL is not an official WinProfile URL: %%U
        exit /b 1
    )
)
if not "!FETCH_URL_COUNT!"=="1" (
    echo ERROR: origin must have exactly one official fetch URL.
    exit /b 1
)
if not "!PUSH_URL_COUNT!"=="1" (
    echo ERROR: origin must have exactly one official push URL.
    exit /b 1
)
exit /b 0

:is_official_origin
set "CANDIDATE_URL=%~1"
if /i "!CANDIDATE_URL!"=="https://github.com/VBlackJack/WinProfile.git" exit /b 0
if /i "!CANDIDATE_URL!"=="https://github.com/VBlackJack/WinProfile" exit /b 0
if /i "!CANDIDATE_URL!"=="git@github.com:VBlackJack/WinProfile.git" exit /b 0
if /i "!CANDIDATE_URL!"=="git@github.com:VBlackJack/WinProfile" exit /b 0
if /i "!CANDIDATE_URL!"=="ssh://git@github.com/VBlackJack/WinProfile.git" exit /b 0
if /i "!CANDIDATE_URL!"=="ssh://git@github.com/VBlackJack/WinProfile" exit /b 0
exit /b 1

:finish
if not defined EXIT_CODE set "EXIT_CODE=0"
if defined DOUBLE_CLICK if not defined NO_PAUSE (
    echo.
    pause
)
endlocal & exit /b %EXIT_CODE%
