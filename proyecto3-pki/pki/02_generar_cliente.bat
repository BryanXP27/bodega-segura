@echo off
set OPENSSL="C:\Program Files\Git\mingw64\bin\openssl.exe"
if not exist %OPENSSL% set OPENSSL=openssl

echo =======================================================
echo [PASO 2] EMISION DE CERTIFICADO DE CLIENTE (X.509 + PFX)
echo =======================================================

if not exist certs\private mkdir certs\private

echo 1. Generando llave privada del cliente en su equipo (RSA 2048)...
%OPENSSL% genrsa -out certs/private/client.key 2048

echo 2. Generando Solicitud de Certificado (CSR) con la llave publica...
%OPENSSL% req -new -key certs/private/client.key -out certs/client.csr -config openssl.cnf -subj "/C=PE/ST=Lima/L=Canete/O=UNDC/OU=Operaciones Bancarias/CN=cliente-desktop-01/emailAddress=operador@boveda.undc.pe"

echo 3. La CA firma el CSR y emite el certificado digital...
%OPENSSL% x509 -req -days 365 -sha256 -in certs/client.csr -CA certs/ca.crt -CAkey certs/private/ca.key -CAcreateserial -out certs/client.crt -extfile openssl.cnf -extensions client_cert

echo 4. Empaquetando en archivo PKCS#12 (.pfx) con password 'password123'...
%OPENSSL% pkcs12 -export -out certs/private/client.pfx -inkey certs/private/client.key -in certs/client.crt -certfile certs/ca.crt -name "BovedaClienteCert" -passout pass:password123

echo.
echo [EXITO] Certificado publico: certs/client.crt
echo [EXITO] Material privado: certs/private/client.key y certs/private/client.pfx (NO versionar)
pause

