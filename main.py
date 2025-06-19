import base64
import json
import os
from datetime import datetime, timezone
from functools import wraps
import random
import hashlib
import time

import psycopg2
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Body, Header
from fastapi.params import Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import StreamingResponse
from pydantic import BaseModel
from typing import List, Any, Optional
import httpx

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

TOKEN_URL = os.environ["TOKEN_URL"]
ODOO_URL = os.environ["ODOO_URL"]
ODOO_DB = os.environ["ODOO_DB"]
ODOO_UID = os.environ["ODOO_UID"]
ODOO_USERNAME = os.environ["ODOO_USERNAME"]
ODOO_PASSWORD = os.environ["ODOO_PASSWORD"]

PAYLOAD = {
    "grant_type": "password",
    "client_id": os.environ["CLIENT_ID"],
    "client_secret": os.environ["CLIENT_SECRET"],
    "username": os.environ["USERNAME"],
    "password": os.environ["PASSWORD"],
}

BOT_URL = os.environ["BOT_URL"]

# Definimos el esquema Bearer para autenticación
security = HTTPBearer()

POSTGRES_USERNAME = os.environ["POSTGRES_USERNAME"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
POSTGRES_HOST = os.environ["POSTGRES_HOST"]
POSTGRES_PORT = os.environ["POSTGRES_PORT"]
POSTGRES_DB = os.environ["POSTGRES_DB"]

# Configuración de la conexión a PostgreSQL
DB_CONFIG = {
    "dbname": POSTGRES_DB,
    "user": POSTGRES_USERNAME,
    "password": POSTGRES_PASSWORD,
    "host": POSTGRES_HOST,
    "port": POSTGRES_PORT,  # Cambia si no es el puerto predeterminado
}

# Establecer conexión global
conn = psycopg2.connect(**DB_CONFIG)
conn.autocommit = True  # Para confirmar automáticamente las transacciones
cursor = conn.cursor()

# Caché en memoria para las peticiones a Odoo
odoo_cache = {}
CACHE_DURATION = 300  # 5 minutos en segundos


def generate_cache_key(data):
    """
    Genera una clave única para la caché basada en los parámetros de la petición.
    """
    # Convertir el diccionario a una cadena ordenada para asegurar consistencia
    data_str = json.dumps(data, sort_keys=True)
    return hashlib.md5(data_str.encode()).hexdigest()


def is_cache_valid(cache_entry):
    """
    Verifica si una entrada en caché aún es válida (menos de 1 hora).
    """
    now = time.time()
    return now - cache_entry["timestamp"] < CACHE_DURATION


# Verifica la expiración
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    # Dividir el token en sus partes
    header, payload, signature = credentials.credentials.split(".")

    # Decodificar Header y Payload desde Base64URL
    decoded_payload = base64.urlsafe_b64decode(payload + "==").decode("utf-8")

    # Convertir a diccionarios de Python
    payload_json = json.loads(decoded_payload)

    # Verifica si el token ha expirado
    exp = payload_json.get("exp")
    if not exp:
        raise HTTPException(
            status_code=400, detail="El token no contiene la fecha de expiración."
        )
    if datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="El token ha caducado.")


# Función para obtener un nuevo token
def get_access_token():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(TOKEN_URL, data=PAYLOAD, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="Error obtaining access token")

    return response.json()


def validate_status_code(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            response = await func(*args, **kwargs)
            # Valida status_code directamente aquí
            data = response.json()
            assert response.status_code == 200, (
                data["error"] if "error" in data else data
            )
            return data
        except HTTPException:
            raise  # reenvía excepciones HTTP sin modificación
        except Exception as e:
            # Captura cualquier otra excepción y envía status_code 500
            raise HTTPException(status_code=500, detail=str(e))

    return wrapper


@app.get("/token")
async def get_token(payload: dict = Depends(verify_token)):
    return get_access_token()


# Endpoint en FastAPI que maneja la lógica
@app.post("/user-question")
def request_data(
    data=Body(),
    id_coversation: str = Header(),
    x_company: str = Header(),
    authorization: str = Header(),
):
    try:

        headers = {
            "Authorization": authorization,
            "id-coversation": id_coversation,
            "x-company": x_company,
        }
        if isinstance(data, bytes):
            data = json.loads(data.decode("utf-8"))
        # Enable streaming by setting stream=True
        external_response = requests.post(
            BOT_URL + "/user-question/", data=data, headers=headers, stream=True
        )

        if external_response.status_code != 200:
            raise HTTPException(
                status_code=external_response.status_code,
                detail="Error fetching external data",
            )

        def event_generator():
            # Iterate over the streaming response from the external API
            for line in external_response.iter_lines():
                if not line:
                    continue
                # Decode the line, elimina los primeros 6 caracteres (ej. "data: ") y parsea el JSON
                try:
                    json_data = json.loads(line.decode("utf-8")[6:])
                    # Re-encode the JSON object to string and add newline separator
                    yield json.dumps(json_data) + "\n"
                except json.JSONDecodeError:
                    # Si ocurre un error en el parseo, se puede omitir la línea o manejar el error
                    continue

        # Return a StreamingResponse with the event generator
        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/user-question")
@validate_status_code
async def get_user_questions(
    id_coversation: str = Header(), authorization: str = Header()
):
    headers = {"Authorization": authorization, "id-coversation": id_coversation}
    return requests.get(BOT_URL + "/user-question/", headers=headers)


@app.delete("/clean-conversation")
@validate_status_code
async def delete_chat(conversation_id: str = Header(), authorization: str = Header()):
    headers = {"Authorization": authorization, "Conversation-Id": conversation_id}
    return requests.delete(BOT_URL + "/clean-conversation/", headers=headers)


@app.post("/bug-report")
@validate_status_code
async def post_bug(
    company_id: str = Header(),
    conversation_id: str = Header(),
    comment: str = Header(),
    authorization: str = Header(),
):
    headers = {
        "Authorization": authorization,
        "Conversation-Id": conversation_id,
        "Company-Id": company_id,
        "Comment": comment,
    }
    return requests.post(f"{BOT_URL}/bug-report/", headers=headers)


@app.get("/create-talk")
@validate_status_code
async def create_talk(authorization: str = Header()):
    return requests.get(
        f"{BOT_URL}/create-talk/", headers={"Authorization": authorization}
    )


@app.get("/talks")
@validate_status_code
async def get_talks(
    id_conversation: str = Query(None),
    user_email: str = Query(),
    authorization: str = Header(),
):
    params = {"user_email": user_email}
    if id_conversation:
        params["id-conversation"] = id_conversation
    return requests.get(
        f"{BOT_URL}/talks/", params=params, headers={"Authorization": authorization}
    )


@app.post("/talks")
@validate_status_code
async def post_talks(data=Body(), authorization: str = Header()):
    return requests.post(
        f"{BOT_URL}/talks/", data=data, headers={"Authorization": authorization}
    )


@app.delete("/talks")
@validate_status_code
async def delete_talks(data=Body(), authorization: str = Header()):
    return requests.delete(
        f"{BOT_URL}/talks/", data=data, headers={"Authorization": authorization}
    )


@app.get("/warnings")
async def warnings():
    try:
        cursor.execute("SELECT data FROM warnings LIMIT 1;")
        result = cursor.fetchone()
        if result is None:
            raise HTTPException(
                status_code=404, detail="No se encontraron advertencias."
            )

        return json.loads(result[0])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/warnings")
async def post_warning(data=Body(...)):
    """
    Endpoint para reemplazar la única advertencia en la tabla 'warnings'.
    """
    try:
        # Eliminar cualquier fila existente
        cursor.execute("DELETE FROM warnings;")
        # Insertar la nueva fila
        cursor.execute("INSERT INTO warnings (data) VALUES (%s);", (json.dumps(data),))
        conn.commit()
        return {"message": "Warning saved successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error al guardar la advertencia: {str(e)}"
        )


@app.post("/odoo")
async def odoo_proxy(data=Body(...)):
    """
    Endpoint para servir como proxy entre el frontend Angular y Odoo.
    Convierte peticiones POST a formato JSONRPC para Odoo.
    Utiliza autenticación estándar de Odoo.
    Incluye caché en memoria con duración de 1 hora.
    """
    try:
        # Preparar la petición JSONRPC para Odoo
        if not isinstance(data, dict):
            if isinstance(data, bytes):
                data = json.loads(data.decode("utf-8"))
            else:
                data = json.loads(data)

        # Generar clave para la caché
        cache_key = generate_cache_key(data)

        # Verificar si la petición está en caché y es válida
        # if cache_key in odoo_cache and is_cache_valid(odoo_cache[cache_key]):
        #     print("Obteniendo respuesta desde caché")
        #     return odoo_cache[cache_key]['response']

        # URL base para JSON-RPC
        jsonrpc_url = f"{ODOO_URL}/jsonrpc"

        # Primero autenticarse para obtener el uid
        auth_params = {
            "service": "common",
            "method": "login",
            "args": [ODOO_DB, ODOO_USERNAME, ODOO_PASSWORD],
        }

        # Realizar la petición de autenticación
        auth_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": auth_params,
            "id": random.randint(0, 1000000000),
        }

        auth_response = requests.post(
            jsonrpc_url, json=auth_data, headers={"Content-Type": "application/json"}
        )

        auth_result = auth_response.json()

        # Verificar si hay error en la autenticación
        if auth_result.get("error"):
            raise HTTPException(
                status_code=401,
                detail=f"Error de autenticación con Odoo: {auth_result['error']}",
            )

        # Obtener el uid del resultado
        uid = auth_result.get("result")

        if not uid:
            raise HTTPException(
                status_code=401,
                detail="Autenticación fallida. UID no encontrado en la respuesta.",
            )

        # Ahora preparar la petición principal
        model = data.get("params", {}).get("model")
        method = data.get("params", {}).get("method")
        args = data.get("params", {}).get("args", [])

        # Construir argumentos para execute
        # Los primeros argumentos siempre son [DB, UID, PASSWORD, MODEL, METHOD]
        execute_args = [ODOO_DB, uid, ODOO_PASSWORD, model, method]

        # Para métodos como search_count, necesitamos desempaquetar los args correctamente
        # Los args en el JSON-RPC deben ser desplegados individualmente, no como una lista completa
        if args:
            # Extender los argumentos en vez de añadir la lista como un único argumento
            execute_args.extend(args)

        # Crear la estructura para la petición de ejecución
        execute_params = {
            "service": "object",
            "method": "execute",
            "args": execute_args,
        }

        # Petición final para ejecutar el método
        execute_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": execute_params,
            "id": random.randint(0, 1000000000),
        }

        # Realizar la petición a Odoo
        execute_response = requests.post(
            jsonrpc_url, json=execute_data, headers={"Content-Type": "application/json"}
        )

        # Obtener la respuesta JSON
        response_json = execute_response.json()

        # Guardar en caché
        odoo_cache[cache_key] = {"response": response_json, "timestamp": time.time()}

        # Limpiar entradas antiguas de la caché (opcional)
        for k in list(odoo_cache.keys()):
            if not is_cache_valid(odoo_cache[k]):
                del odoo_cache[k]

        # Devolver la respuesta de Odoo al frontend
        return response_json

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error en la comunicación con Odoo: {str(e)}"
        )


class OdooPayload(BaseModel):
    model: str
    method: str
    args: Optional[List[Any]] = []
    fields: Optional[List[str]] = []
    offset: Optional[int] = None
    limit: Optional[int] = None
    order: Optional[str] = None
    groupby: Optional[List[str]] = []
    aggregates: Optional[List[str]] = []
    lazy: Optional[bool] = False


@app.post("/odoo/execute")
async def odoo_execute(payload: OdooPayload):
    """
    Endpoint para servir como proxy entre el frontend Angular y Odoo.
    Convierte peticiones POST a formato JSONRPC para Odoo.
    Utiliza autenticación estándar de Odoo.
    Incluye caché en memoria con duración de 1 hora.
    """

    # Validate that we have at least one arg to build the RPC call
    if not payload.args and payload.method != "fields_get":
        raise HTTPException(status_code=400, detail="No arguments to execute")

    # Generar clave para la caché
    cache_key = generate_cache_key(payload.__dict__)

    # Verificar si la petición está en caché y es válida
    if cache_key in odoo_cache and is_cache_valid(odoo_cache[cache_key]):
        print("Obteniendo respuesta desde caché")
        return odoo_cache[cache_key]["response"]

    # Base RPC args: [db, uid, password, model, method]
    execute_args: List[Any] = [
        ODOO_DB,
        ODOO_UID,
        ODOO_PASSWORD,
        payload.model,
        payload.method,
    ]

    # Materialize JSON arguments into Python types
    domain_or_ids = payload.args

    # Build the rest of the args by method type
    if payload.method == "search":
        # search(domain, offset, limit, order)
        execute_args += [
            domain_or_ids,
            payload.offset,
            payload.limit,
            payload.order,
        ]
    elif payload.method == "search_read":
        # search_read(domain, fields, offset, limit, order)
        execute_args += [
            domain_or_ids,
            payload.fields,
            payload.offset,
            payload.limit,
            payload.order,
        ]
    elif payload.method == "read":
        # read(ids, fields)
        execute_args += [
            domain_or_ids,
            payload.fields,
        ]
    elif payload.method == "search_count":
        # search_count(domain)
        execute_args += [
            domain_or_ids,
        ]
    elif payload.method == "read_group":
        # read_group(domain, aggregates, groupby, offset, limit, order)
        execute_args += [
            domain_or_ids,
            payload.aggregates,
            payload.groupby,
            payload.offset,
            payload.limit,
            payload.order,
            len(payload.groupby) < 2 or payload.lazy,
        ]
    elif payload.method == "fields_get":
        # fields_get(fields)
        execute_args += [
            [],
            payload.fields,
        ]
    else:
        # Defender against unexpected methods
        raise HTTPException(
            status_code=400, detail=f"Unsupported method: {payload.method}"
        )

    # Construct the JSON-RPC request body
    rpc_body = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {"service": "object", "method": "execute", "args": execute_args},
        "id": random.randint(1, 2**31 - 1),
    }

    # Use httpx for async HTTP POST
    async with httpx.AsyncClient() as client:
        resp = await client.post(ODOO_URL + "/jsonrpc", json=rpc_body, timeout=30.0)

    # If Odoo returns an HTTP error, propagate it
    data = resp.json()
    if resp.status_code >= 400 or data.get("error"):
        raise HTTPException(
            status_code=500 if resp.status_code < 400 else resp.status_code,
            detail=data.get("error", {}).get("data", {}),
        )

    result = data.get("result", {})

    # Guardar en caché
    odoo_cache[cache_key] = {"response": result, "timestamp": time.time()}

    # Limpiar entradas antiguas de la caché (opcional)
    for k in list(odoo_cache.keys()):
        if not is_cache_valid(odoo_cache[k]):
            del odoo_cache[k]

    # Return result to the caller
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app)
