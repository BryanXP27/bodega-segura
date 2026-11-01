@echo off
set OPENSSL="C:\Program Files\Git\mingw64\bin\openssl.exe"
if not exist %OPENSSL% set OPENSSL=openssl

echo =======================================================
echo [PASO 1] CREANDO AUTORIDAD CERTIFICADORA (ROOT CA)
echo =======================================================

if not exist certs mkdir certs

echo 1. Generando llave privada de la CA (RSA 4096)...
%OPENSSL% genrsa -out certs/ca.key 4096

echo 2. Generando certificado raiz autofirmado X.509 (10 anos)...
%OPENSSL% req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt -config openssl.cnf -extensions v3_ca -subj "/C=PE/ST=Lima/L=Canete/O=UNDC - Seguridad Informatica/OU=Root CA/CN=Boveda Segura Root CA/emailAddress=pki@undc.edu.pe"

echo.
echo [EXITO] CA Raiz creada en certs/ca.key y certs/ca.crt
pause

