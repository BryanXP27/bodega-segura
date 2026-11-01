# Dockerfile para Servidor API mTLS en Google Cloud Run (Proyecto 3)
FROM python:3.11-slim

WORKDIR /app

# Copiar certificados y codigo
COPY pki/certs /app/pki/certs
COPY api/server.py /app/api/server.py

ENV PORT=8443
EXPOSE 8443

CMD ["python", "api/server.py"]

