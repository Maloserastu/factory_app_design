# Usa una imagen base de Python
FROM python:3.12-slim

# Evita buffers y bytecode
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Directorio de trabajo
WORKDIR /app

# Copiar dependencias si usas requirements.txt
COPY requirements.txt .

# Instalar dependencias
RUN pip install --no-cache-dir -r requirements.txt

#Copiar el código del backend
COPY . .

#Exponer el puerto
EXPOSE 8000

#Comando por defecto
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
