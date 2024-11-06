import os
import random

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware

load_dotenv(override=True)

app = FastAPI()

# Configurar el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir el origen de tu app Next.js
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permitir todos los headers
)

TOKEN_URL = os.environ['TOKEN_URL']
PUBLIC_API_TOKEN_URL = os.environ['PUBLIC_API_TOKEN_URL']

PAYLOAD = {
    'grant_type': 'password',
    'client_id': os.environ['CLIENT_ID'],
    'client_secret': os.environ['CLIENT_SECRET'],
    'username': os.environ['USERNAME'],
    'password': os.environ['PASSWORD']
}

# PublicApi credentials
PUBLIC_API_PAYLOAD = {
    'grant_type': 'client_credentials',
    'client_id': os.environ['PUBLIC_API_CLIENT_ID'],
    'client_secret': os.environ['PUBLIC_API_CLIENT_SECRET'],
    'scope': os.environ['PUBLIC_API_SCOPE']
}


# Función para obtener un nuevo token
def get_access_token(public_api: bool = False):
    payload = PAYLOAD
    url = TOKEN_URL
    if public_api:
        payload = PUBLIC_API_PAYLOAD
        url = PUBLIC_API_TOKEN_URL

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(url, data=payload, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error obtaining access token")

    return response.json().get('access_token')


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
            'Comment': str(comment)
        }
        external_response = requests.post(
            'https://mojito360-bed5bfgee5g4cthk.northeurope-01.azurewebsites.net/api/bug-report/',
            headers=headers
        )
        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/companies")
def get_companies():
    try:
        access_token = get_access_token(True)
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        return requests.get('https://webapi.mojito360.com/api/companies', headers=headers).json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
