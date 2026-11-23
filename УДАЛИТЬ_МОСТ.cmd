@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0bridge\bridge_ctl.ps1" -Action uninstall
