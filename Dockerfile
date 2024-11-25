FROM python:3.12

# Establece el directorio de trabajo dentro del contenedor
WORKDIR /code

# Copia los archivos de requisitos primero para aprovechar la caché de capas de Docker
COPY requirements.txt ./
COPY main.py ./
COPY .env ./

# Crea la carpeta de logs a compartir
RUN mkdir ".logs"

# Instala las dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt
RUN which gunicorn

# Comando para ejecutar tu aplicación con gunicorn
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--bind", "0.0.0.0:8000"]
