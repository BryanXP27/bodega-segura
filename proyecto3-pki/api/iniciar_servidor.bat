@echo off
set PYTHON="C:\Users\Lenovo\AppData\Local\Programs\Python\Python311\python.exe"
if not exist %PYTHON% set PYTHON=python

echo ======================================================
echo INICIANDO API CON mTLS (PROYECTO 3 - UNDC 2026)
echo ======================================================
%PYTHON% server.py
pause

