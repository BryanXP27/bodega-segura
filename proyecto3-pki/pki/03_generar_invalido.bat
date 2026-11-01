@echo off
set OPENSSL="C:\Program Files\Git\mingw64\bin\openssl.exe"
if not exist %OPENSSL% set OPENSSL=openssl

echo =======================================================
echo [PASO 3] GENERACION DE CERTIFICADO DE OTRA CA (ATAQUE)
echo =======================================================

echo 1. Creando CA no autorizada (Rogue CA)...
%OPENSSL% genrsa -out certs/fake_ca.key 2048
%OPENSSL% req -new -x509 -days 365 -key certs/fake_ca.key -out certs/fake_ca.crt -subj "/C=XX/ST=Unknown/L=Nowhere/O=CA Atacante/CN=Rogue Malicious Root CA"

echo 2. Generando llave y CSR del atacante...
%OPENSSL% genrsa -out certs/attacker.key 2048
%OPENSSL% req -new -key certs/attacker.key -out certs/attacker.csr -subj "/C=XX/ST=Unknown/L=Nowhere/O=Atacante/CN=hacker-client"

echo 3. Firmando con la CA falsa...
%OPENSSL% x509 -req -days 365 -in certs/attacker.csr -CA certs/fake_ca.crt -CAkey certs/fake_ca.key -CAcreateserial -out certs/attacker.crt
%OPENSSL% pkcs12 -export -out certs/attacker.pfx -inkey certs/attacker.key -in certs/attacker.crt -passout pass:password123

echo.
echo [EXITO] Certificado atacante generado en certs/attacker.pfx
pause

