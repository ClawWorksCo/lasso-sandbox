@echo off
REM Thin launcher for Windows Terminal pane integration.
REM Usage: lasso-launch.cmd [project-dir]
REM
REM Designed for use in Windows Terminal split-pane profiles.
REM Avoids quoting issues with wt.exe arguments.

set "PROJECT_DIR=%~1"
if "%PROJECT_DIR%"=="" set "PROJECT_DIR=%CD%"

lasso up --resume --dir "%PROJECT_DIR%"
