# ============================================================
# CERBERUS V3.5 - DOCKERFILE SIMPLIFICADO PARA RENDER
# ============================================================

FROM python:3.11-slim

# Variables de entorno
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=UTC

# Crear directorio de trabajo
WORKDIR /app

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias (solo las necesarias)
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY app/ ./app/

# Crear usuario no-root
RUN adduser --disabled-password --gecos "" cerberus && \
    chown -R cerberus:cerberus /app

# Cambiar a usuario no-root
USER cerberus

# Puerto
EXPOSE 8000

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]