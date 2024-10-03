import os

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware

load_dotenv(override=True)

app = FastAPI()

# Configurar el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://inn-chat-bot.vercel.app/"],  # Permitir el origen de tu app Next.js
    allow_credentials=True,
    allow_methods=["*"],  # Permitir todos los métodos (GET, POST, etc.)
    allow_headers=["*"],  # Permitir todos los headers
)

TOKEN_URL = os.environ['TOKEN_URL']
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
USERNAME = os.environ['USERNAME']
PASSWORD = os.environ['PASSWORD']


# Función para obtener un nuevo token
def get_access_token():
    payload = {
        'grant_type': 'password',
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'username': USERNAME,
        'password': PASSWORD
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    response = requests.post(TOKEN_URL, data=payload, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error obtaining access token")

    return response.json().get('access_token')


# Endpoint en FastAPI que maneja la lógica
@app.post("/chat")
def request_data(message: str = Body()):
    try:
        # 1. Obtener el token
        access_token = get_access_token()

        # 2. Usar el token para hacer la petición a la API externa
        headers = {
            'Authorization': f'Bearer {access_token}',
            'id-coversation': '0001',
            'x-company': '1066'
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
        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
