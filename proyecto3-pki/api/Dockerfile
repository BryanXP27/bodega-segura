# Dockerfile para el API mTLS (Proyecto 3)
# Ejecutar en una VM / entorno con TLS de entrada (Cloud Run NO soporta mTLS con CA propia).
FROM python:3.11-slim

WORKDIR /app

# Solo material PUBLICO. Las llaves privadas se montan como secreto en runtime.
COPY pki/certs/ca.crt pki/certs/server.crt /app/pki/certs/
COPY api/server.py /app/api/server.py

ENV PORT=8443
ENV SERVER_KEY=/run/secrets/server.key
EXPOSE 8443

CMD ["python", "api/server.py"]
