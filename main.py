import base64
import json
import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

load_dotenv(override=True)

app = FastAPI()

# Configurar el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://innovation-xi.vercel.app"],  # Solo permitir este origen
    allow_credentials=True,
    allow_methods=["POST"],  # Solo permitir el método GET
    allow_headers=["*"],  # Permitir todos los headers
)

TOKEN_URL = os.environ['TOKEN_URL']

PAYLOAD = {
    'grant_type': 'password',
    'client_id': os.environ['CLIENT_ID'],
    'client_secret': os.environ['CLIENT_SECRET'],
    'username': os.environ['USERNAME'],
    'password': os.environ['PASSWORD']
}

# Definimos el esquema Bearer para autenticación
security = HTTPBearer()


# Verifica la expiración
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Dividir el token en sus partes
    header, payload, signature = credentials.credentials.split('.')

    # Decodificar Header y Payload desde Base64URL
    decoded_payload = base64.urlsafe_b64decode(payload + '==').decode('utf-8')

    # Convertir a diccionarios de Python
    payload_json = json.loads(decoded_payload)

    # Verifica si el token ha expirado
    exp = payload_json.get("exp")
    if not exp:
        raise HTTPException(
            status_code=400, detail="El token no contiene la fecha de expiración."
        )
    if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=401, detail="El token ha caducado."
        )


# Función para obtener un nuevo token
def get_access_token():
    response = requests.post(TOKEN_URL, data=PAYLOAD, headers={'Content-Type': 'application/x-www-form-urlencoded'})

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error obtaining access token")

    return response.json()


# Endpoint protegido
@app.get("/token")
async def get_token(payload: dict = Depends(verify_token)):
    return get_access_token()
