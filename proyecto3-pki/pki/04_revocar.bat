@echo off
chcp 65001 > nul
title Proyecto 3 - Revocar certificado y regenerar CRL
echo ================================================================
echo  REVOCACION DE CERTIFICADO - PROYECTO 3 (UNDC 2026)
echo ================================================================
echo.
echo Uso:
echo  04_revocar.bat --cert certs\client-revocado.crt --reason keyCompromise
echo.
python "%~dp004_revocar.py" %*
pause
