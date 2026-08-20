@echo off
REM Copyright 2026 Julien Bombled
REM Licensed under the Apache License, Version 2.0.
REM
REM WinProfile guarded release launcher.
REM The GitHub tag workflow performs the authoritative MSVC build and signing.
REM
REM Usage:
REM   Release.bat [check] [no-pause]
REM   Release.bat [no-pause]

setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"
title WinProfile - Release

set "REPOSITORY=VBlackJack/WinProfile"
set "CHECK_ONLY="
set "NO_PAUSE="
set "DOUBLE_CLICK="
set "ARGUMENT_ERROR="
echo %CMDCMDLINE% | find /i "/c" >nul && set "DOUBLE_CLICK=1"

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="check"    (set "CHECK_ONLY=1" & shift & goto :parse_args)
if /i "%~1"=="no-pause" (set "NO_PAUSE=1"   & shift & goto :parse_args)
echo Unknown option: %~1
set "ARGUMENT_ERROR=1"
shift
goto :parse_args

:args_done
if defined ARGUMENT_ERROR (
    echo Usage: Release.bat [check] [no-pause]
    set "EXIT_CODE=2"
    goto :finish
)
set "VERSION="
for /f "tokens=3" %%V in ('findstr /r /c:"^version = " Cargo.toml 2^>nul') do if not defined VERSION set "VERSION=%%~V"
if not defined VERSION (
    echo ERROR: workspace version was not found in Cargo.toml.
    set "EXIT_CODE=1"
    goto :finish
)
set "TAG=v!VERSION!"
set "RELEASE_NOTES=docs\release-v!VERSION!.md"
set "APPROVAL_FILE=work-private-docs\release-!TAG!.approved"
if not exist "!RELEASE_NOTES!" (
    echo ERROR: release notes are missing: !RELEASE_NOTES!
    set "EXIT_CODE=1"
    goto :finish
)

set "GIT_COMMAND=git"
set "GH_COMMAND=gh"
if /i "%WINPROFILE_BATCH_TEST_MODE%"=="1" (
    if defined WINPROFILE_TEST_GIT set "GIT_COMMAND=%WINPROFILE_TEST_GIT%"
    if defined WINPROFILE_TEST_GH set "GH_COMMAND=%WINPROFILE_TEST_GH%"
) else (
    where git.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: git.exe was not found.
        set "EXIT_CODE=9009"
        goto :finish
    )
    where gh.exe >nul 2>&1
    if errorlevel 1 (
        echo ERROR: GitHub CLI gh.exe was not found.
        set "EXIT_CODE=9009"
        goto :finish
    )
)

if not exist "%~dp0.git" (
    echo ERROR: releases require the canonical Git worktree.
    set "EXIT_CODE=1"
    goto :finish
)
call "!GIT_COMMAND!" rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo ERROR: repository metadata could not be read.
    set "EXIT_CODE=1"
    goto :finish
)

set "BRANCH="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" branch --show-current 2^>nul') do set "BRANCH=%%A"
if /i not "!BRANCH!"=="main" (
    echo ERROR: releases must start from main, not !BRANCH!.
    set "EXIT_CODE=1"
    goto :finish
)

call :require_clean_tree
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)
call :validate_origin
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)

call "!GIT_COMMAND!" fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main"
if errorlevel 1 (
    echo ERROR: origin/main could not be fetched.
    set "EXIT_CODE=1"
    goto :finish
)
set "HEAD_SHA="
set "REMOTE_SHA="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse HEAD 2^>nul') do set "HEAD_SHA=%%A"
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse origin/main 2^>nul') do set "REMOTE_SHA=%%A"
if not defined HEAD_SHA (
    echo ERROR: HEAD could not be resolved.
    set "EXIT_CODE=1"
    goto :finish
)
if /i not "!HEAD_SHA!"=="!REMOTE_SHA!" (
    echo ERROR: local main and origin/main are not aligned.
    set "EXIT_CODE=1"
    goto :finish
)

call :validate_approval
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)

set "CI_CONCLUSION="
for /f "delims=" %%A in ('call "!GH_COMMAND!" run list --repo "!REPOSITORY!" --workflow CI --commit "!HEAD_SHA!" --limit 1 --json conclusion --jq ".[0].conclusion" 2^>nul') do set "CI_CONCLUSION=%%A"
if /i not "!CI_CONCLUSION!"=="success" (
    echo ERROR: the exact main commit does not have a successful CI run.
    set "EXIT_CODE=1"
    goto :finish
)

set "HAS_CERTIFICATE="
set "HAS_PASSWORD="
set "HAS_TIMESTAMP="
for /f "delims=" %%S in ('call "!GH_COMMAND!" secret list --repo "!REPOSITORY!" --json name --jq ".[].name" 2^>nul') do (
    if "%%S"=="WINDOWS_SIGNING_CERTIFICATE_BASE64" set "HAS_CERTIFICATE=1"
    if "%%S"=="WINDOWS_SIGNING_CERTIFICATE_PASSWORD" set "HAS_PASSWORD=1"
    if "%%S"=="WINDOWS_SIGNING_TIMESTAMP_URL" set "HAS_TIMESTAMP=1"
)
if not defined HAS_CERTIFICATE (
    echo ERROR: missing exact GitHub Actions secret WINDOWS_SIGNING_CERTIFICATE_BASE64.
    set "EXIT_CODE=1"
    goto :finish
)
if not defined HAS_PASSWORD (
    echo ERROR: missing exact GitHub Actions secret WINDOWS_SIGNING_CERTIFICATE_PASSWORD.
    set "EXIT_CODE=1"
    goto :finish
)
if not defined HAS_TIMESTAMP (
    echo ERROR: missing exact GitHub Actions secret WINDOWS_SIGNING_TIMESTAMP_URL.
    set "EXIT_CODE=1"
    goto :finish
)

call :require_tag_absent
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)

echo Running local quality gates...
call "%~dp0Test.bat" no-pause
if errorlevel 1 (
    set "EXIT_CODE=!ERRORLEVEL!"
    goto :finish
)

if not defined CHECK_ONLY (
    echo.
    echo Local gates passed. The release state will be revalidated after confirmation.
    set "CONFIRM="
    set /p "CONFIRM=Type !TAG! to publish: "
    if /i not "!CONFIRM!"=="!TAG!" (
        echo Release cancelled.
        set "EXIT_CODE=2"
        goto :finish
    )
)

call :final_revalidation
if errorlevel 1 (
    set "EXIT_CODE=1"
    goto :finish
)

echo.
echo Release preflight passed for !TAG! at !HEAD_SHA!.
if defined CHECK_ONLY (
    set "EXIT_CODE=0"
    goto :finish
)

call "!GIT_COMMAND!" tag -a "!TAG!" "!HEAD_SHA!" -m "WinProfile !VERSION!"
if errorlevel 1 (
    echo ERROR: tag creation failed.
    set "EXIT_CODE=1"
    goto :finish
)
call "!GIT_COMMAND!" push origin "!TAG!"
if errorlevel 1 (
    echo ERROR: tag push failed. The local tag remains for operator review.
    set "EXIT_CODE=1"
    goto :finish
)

echo.
echo Release workflow triggered:
echo https://github.com/!REPOSITORY!/actions/workflows/release.yml
set "EXIT_CODE=0"
goto :finish

:final_revalidation
call :require_clean_tree
if errorlevel 1 exit /b 1
set "CURRENT_HEAD="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse HEAD 2^>nul') do set "CURRENT_HEAD=%%A"
if /i not "!CURRENT_HEAD!"=="!HEAD_SHA!" (
    echo ERROR: HEAD changed after the quality gates; release refused.
    exit /b 1
)
call :validate_origin
if errorlevel 1 exit /b 1
call "!GIT_COMMAND!" fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main"
if errorlevel 1 (
    echo ERROR: final origin/main refresh failed.
    exit /b 1
)
set "FINAL_REMOTE_SHA="
for /f "delims=" %%A in ('call "!GIT_COMMAND!" rev-parse origin/main 2^>nul') do set "FINAL_REMOTE_SHA=%%A"
if /i not "!FINAL_REMOTE_SHA!"=="!HEAD_SHA!" (
    echo ERROR: origin/main changed after the quality gates; release refused.
    exit /b 1
)
if not exist "!RELEASE_NOTES!" (
    echo ERROR: release notes disappeared after the quality gates.
    exit /b 1
)
call :validate_approval
if errorlevel 1 exit /b 1
call :require_tag_absent
if errorlevel 1 exit /b 1
exit /b 0

:require_clean_tree
call :measure_clean_tree
if errorlevel 1 exit /b 1
if not "!DIRTY!"=="0" (
    echo ERROR: the worktree has !DIRTY! uncommitted path^(s^).
    exit /b 1
)
exit /b 0

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
if not defined STATUS_CONTAINER set "STATUS_CONTAINER=!STATUS_ROOT!\winprofile-release-git-status-!RANDOM!-!RANDOM!"
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

:validate_approval
if not exist "!APPROVAL_FILE!" (
    echo ERROR: release VM approval is missing.
    echo Complete the private checklist, then create the exact marker:
    echo   !APPROVAL_FILE!
    exit /b 1
)
set "APPROVAL_LINES="
for /f %%A in ('findstr /n /r /c:".*" "!APPROVAL_FILE!" ^| find /c ":"') do set "APPROVAL_LINES=%%A"
if not "!APPROVAL_LINES!"=="4" goto :invalid_approval
findstr /n /r /c:".*" "!APPROVAL_FILE!" | findstr /x /l /c:"1:WINPROFILE_RELEASE_VM_APPROVAL_V1" >nul || goto :invalid_approval
findstr /n /r /c:".*" "!APPROVAL_FILE!" | findstr /x /l /c:"2:tag=!TAG!" >nul || goto :invalid_approval
findstr /n /r /c:".*" "!APPROVAL_FILE!" | findstr /x /l /c:"3:commit=!HEAD_SHA!" >nul || goto :invalid_approval
findstr /n /r /c:".*" "!APPROVAL_FILE!" | findstr /x /l /c:"4:result=approved" >nul || goto :invalid_approval
exit /b 0

:invalid_approval
echo ERROR: release VM approval marker is malformed or does not match !TAG! at !HEAD_SHA!.
exit /b 1

:require_tag_absent
call "!GIT_COMMAND!" rev-parse -q --verify "refs/tags/!TAG!" >nul 2>&1
set "LOCAL_TAG_RESULT=!ERRORLEVEL!"
if "!LOCAL_TAG_RESULT!"=="0" (
    echo ERROR: local tag !TAG! already exists.
    exit /b 1
)
if not "!LOCAL_TAG_RESULT!"=="1" (
    echo ERROR: local tag state could not be inspected.
    exit /b 1
)
call "!GIT_COMMAND!" ls-remote --exit-code --tags origin "refs/tags/!TAG!" >nul 2>&1
set "REMOTE_TAG_RESULT=!ERRORLEVEL!"
if "!REMOTE_TAG_RESULT!"=="0" (
    echo ERROR: remote tag !TAG! already exists.
    exit /b 1
)
if not "!REMOTE_TAG_RESULT!"=="2" (
    echo ERROR: remote tag state could not be inspected.
    exit /b 1
)
exit /b 0

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
