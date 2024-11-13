import base64
import json
import os
import random
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

load_dotenv(override=True)

app = FastAPI()

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
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(TOKEN_URL, data=PAYLOAD, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error obtaining access token")

    return response.json()


# Endpoint protegido
@app.get("/token")
async def get_token(payload: dict = Depends(verify_token)):
    return get_access_token()


# Endpoint en FastAPI que maneja la lógica
@app.post("/chat")
def request_data(
        message: str = Body(),
        conversationId: int = Body(None),
        companyId: int = Body(None)
):
    try:
        if not conversationId:
            conversationId = random.randint(1, 9999)

        # 1. Obtener el token
        access_token = get_access_token()

        # 2. Usar el token para hacer la petición a la API externa
        headers = {
            'Authorization': f'Bearer {access_token}',
            'id-coversation': str(conversationId),
            'x-company': str(companyId)
        }
        external_response = requests.post(
            'https://mojito360-bed5bfgee5g4cthk.northeurope-01.azurewebsites.net/api/user-question/',
            data={'input_question': message},
            headers=headers
        )

        # 3. Si la respuesta de la API externa no es 200, devolver un error
        if external_response.status_code != 200:
            raise HTTPException(status_code=external_response.status_code, detail="Error fetching external data")

        # 4. Retornar la respuesta de la API externa como la respuesta del endpoint
        return {**external_response.json(), 'conversationId': conversationId}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/chat/{conversationId}")
def delete_chat(
        conversationId: int,
):
    try:
        # 1. Obtener el token
        access_token = get_access_token()

        # 2. Usar el token para hacer la petición a la API externa
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Conversation-Id': str(conversationId)
        }
        external_response = requests.delete(
            'https://mojito360-bed5bfgee5g4cthk.northeurope-01.azurewebsites.net/api/clean-conversation/',
            headers=headers
        )
        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/bug")
def post_bug(
        companyId: int = Body(),
        conversationId: int = Body(),
        comment: str = Body()
):
    try:

        # 1. Obtener el token
        access_token = get_access_token()

        # 2. Usar el token para hacer la petición a la API externa
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Conversation-Id': str(conversationId),
            'Company-Id': str(companyId),
            'Comment': comment
        }
        external_response = requests.post(
            'https://mojito360-bed5bfgee5g4cthk.northeurope-01.azurewebsites.net/api/bug-report/',
            headers=headers
        )
        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
