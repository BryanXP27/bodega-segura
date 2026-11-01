@echo off
set PYTHON="C:\Users\Lenovo\AppData\Local\Programs\Python\Python311\python.exe"
if not exist %PYTHON% set PYTHON=python

echo ========================================================
echo INICIANDO APLICATIVO DE ESCRITORIO mTLS (PROYECTO 3)
echo ========================================================
start "" %PYTHON% app.py

