import base64
import json
import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Body, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.cors import CORSMiddleware

load_dotenv(override=True)

app = FastAPI()

# Configurar el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Solo permitir este origen
    allow_credentials=True,
    allow_methods=["*"],  # Solo permitir el método GET
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

BOT_URL = os.environ['BOT_URL']
AZURE_URL = os.environ['AZURE_URL']

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
@app.post("/user-question")
def request_data(
        data=Body(),
        id_coversation: str = Header(),
        x_company: str = Header(),
        authorization: str = Header()
):
    try:

        headers = {
            'Authorization': authorization,
            'id-coversation': id_coversation,
            'x-company': x_company
        }
        external_response = requests.post(
            BOT_URL + '/user-question/',
            data={'input_question': data.get('input_question')},
            headers=headers
        )

        if external_response.status_code != 200:
            raise HTTPException(status_code=external_response.status_code, detail="Error fetching external data")

        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/clean-conversation")
def delete_chat(
        conversation_id: str = Header(),
        authorization: str = Header()
):
    try:
        headers = {
            'Authorization': authorization,
            'Conversation-Id': conversation_id
        }
        external_response = requests.delete(
            BOT_URL + '/clean-conversation/',
            headers=headers
        )
        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/bug-report")
async def post_bug(
        company_id: str = Header(),
        conversation_id: str = Header(),
        comment: str = Body(),
        authorization: str = Header()
):
    try:

        headers = {
            'Authorization': authorization,
            'Conversation-Id': conversation_id,
            'Company-Id': company_id,
            'Comment': comment
        }
        response = requests.post(f"{BOT_URL}/bug-report/", headers=headers)

        return response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
