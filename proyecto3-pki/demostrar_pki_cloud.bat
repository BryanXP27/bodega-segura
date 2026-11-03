@echo off
title DEMOSTRACION EN CONSOLA - PROYECTO 3 (UNDC 2026)
set PYTHON="C:\Users\Lenovo\AppData\Local\Programs\Python\Python311\python.exe"
if not exist %PYTHON% set PYTHON=python

%PYTHON% demostrar_pki_cloud.py
pause
