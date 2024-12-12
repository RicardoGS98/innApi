import base64
import json
import os
import sqlite3
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Body, Header
from fastapi.params import Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.cors import CORSMiddleware

load_dotenv(override=True)

app = FastAPI()

# Configurar el middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],  # Permitir todos los headers
)

# Conectar a SQLite
conn = sqlite3.connect("warnings.db", check_same_thread=False)
cursor = conn.cursor()

# Crear tabla (si no existe)
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS warnings (
        data TEXT NOT NULL
    )
    """
)
conn.commit()

TOKEN_URL = os.environ['TOKEN_URL']

PAYLOAD = {
    'grant_type': 'password',
    'client_id': os.environ['CLIENT_ID'],
    'client_secret': os.environ['CLIENT_SECRET'],
    'username': os.environ['USERNAME'],
    'password': os.environ['PASSWORD']
}

BOT_URL = os.environ['BOT_URL']

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
            data=data,
            headers=headers
        )

        if external_response.status_code != 200:
            raise HTTPException(status_code=external_response.status_code, detail="Error fetching external data")

        return external_response.json()

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/user-question")
def get_user_questions(
        id_coversation: str = Header(),
        authorization: str = Header()
):
    try:

        headers = {
            'Authorization': authorization,
            'id-coversation': id_coversation
        }
        external_response = requests.get(
            BOT_URL + '/user-question/',
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
        comment: str = Header(),
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


@app.get("/create-talk")
async def create_talk(authorization: str = Header()):
    try:
        response = requests.get(f"{BOT_URL}/create-talk/", headers={'Authorization': authorization})
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/talks")
async def get_talks(
        id_conversation: str = Query(None),
        user_email: str = Query(),
        authorization: str = Header()
):
    try:
        params = {"user_email": user_email}
        if id_conversation:
            params["id-conversation"] = id_conversation
        response = requests.get(f"{BOT_URL}/talks/", params=params, headers={'Authorization': authorization})
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/talks")
async def post_talks(
        data=Body(),
        authorization: str = Header()
):
    try:
        response = requests.post(f"{BOT_URL}/talks/", data=data, headers={'Authorization': authorization})
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/talks")
async def delete_talks(
        id_conversation: str = Header(),
        authorization: str = Header()
):
    try:
        response = requests.delete(
            f"{BOT_URL}/talks/",
            headers={'Authorization': authorization, 'id-conversation': id_conversation}
        )
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/warnings')
async def warnings():
    try:
        cursor.execute("SELECT * FROM warnings;")
        results = cursor.fetchall()
        return [{"id": row[0], "data": row[1]} for row in results]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/warnings')
async def post_warning(data=Body(...)):
    try:
        cursor.execute("UPDATE warnings SET data=? WHERE data IS NOT NULL;", (json.dumps(data),))
        conn.commit()
        return {"message": "Warning saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == '__main__':
    import uvicorn

    uvicorn.run(app)
