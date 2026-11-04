@echo off
set OPENSSL="C:\Program Files\Git\mingw64\bin\openssl.exe"
if not exist %OPENSSL% set OPENSSL=openssl

echo =======================================================
echo [PASO 3] GENERACION DE CERTIFICADO DE OTRA CA (ATAQUE)
echo =======================================================

if not exist certs\private mkdir certs\private

echo 1. Creando CA no autorizada (Rogue CA)...
%OPENSSL% genrsa -out certs/private/fake_ca.key 2048
%OPENSSL% req -new -x509 -days 365 -sha256 -key certs/private/fake_ca.key -out certs/fake_ca.crt -subj "/C=XX/ST=Unknown/L=Nowhere/O=CA Atacante/CN=Rogue Malicious Root CA"

echo 2. Generando llave y CSR del atacante...
%OPENSSL% genrsa -out certs/private/attacker.key 2048
%OPENSSL% req -new -key certs/private/attacker.key -out certs/attacker.csr -subj "/C=XX/ST=Unknown/L=Nowhere/O=Atacante/CN=hacker-client"

echo 3. Firmando con la CA falsa...
%OPENSSL% x509 -req -days 365 -sha256 -in certs/attacker.csr -CA certs/fake_ca.crt -CAkey certs/private/fake_ca.key -CAcreateserial -out certs/attacker.crt
%OPENSSL% pkcs12 -export -out certs/private/attacker.pfx -inkey certs/private/attacker.key -in certs/attacker.crt -passout pass:password123

echo.
echo [EXITO] Certificado publico del atacante: certs/attacker.crt
echo [EXITO] Material privado: certs/private/attacker.* (NO versionar)
pause

