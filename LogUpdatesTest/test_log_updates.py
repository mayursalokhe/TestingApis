import requests
import pytest
from models import Payload, LogEntry, Response, EmailValid
import datetime
import json
from pydantic import ValidationError, EmailStr
import pyotp
import threading
import time 
import jwt

BASE_URL = "https://beta.tradefinder.in/api_be/admin/log_updates"

SECRET_KEY = pyotp.random_base32()

lock = threading.Lock()

token_data = {
    'jwttoken': None,
    'accesstoken': None
}

# Check token expired or not
def is_token_expired(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get("exp")
        if exp:
            return time.time() > exp
        return True
    except Exception as e:
        print(f"Error decoding token: {e}")
        return True

# JWT TOKEN Func
def get_jwttoken():
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNkZTg4NmYyMWE3MzExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0Nzc0NTEyLjY2MTMzLCJleHAiOjE3NDQ3OTA0MzEuNTM4MDMsInBsYW4iOiJESUFNT05EIiwidXNlcl90eXBlIjoiY2xpZW50IiwiYWNjZXNzIjoie1wibWFya2V0X3B1bHNlXCI6IDEsIFwiaW5zaWRlcl9zdHJhdGVneVwiOiAwLCBcInNlY3Rvcl9zY29wZVwiOiAwLCBcInN3aW5nX3NwZWN0cnVtXCI6IDAsIFwib3B0aW9uX2Nsb2NrXCI6IDAsIFwib3B0aW9uX2FwZXhcIjogMCwgXCJwYXJ0bmVyX3Byb2dyYW1cIjogMH0iLCJhY2NvdW50X2V4cCI6IjE3NzYxOTE0MDAiLCJicm9rZXIiOiIifQ.ULZ4DSYlcXxr7dvDgiQGQB9PV-6PNCQUsRtQ6mMAT74"

# ACCESS TOKEN Func
def get_accesstoken():
    accesstoken_obj = pyotp.TOTP(SECRET_KEY, interval=30)
    return accesstoken_obj.now()  


def refresh_tokens():
    while True:
        with lock:
            if token_data['jwttoken'] is None or is_token_expired(token_data['jwttoken']):
                print("Refreshing JWT Token")
                token_data['jwttoken'] = get_jwttoken()
            token_data['accesstoken'] = get_accesstoken()
        time.sleep(30)

token_refresher = threading.Thread(target=refresh_tokens, daemon=True)
token_refresher.start()

@pytest.fixture(scope="module")
def auth_headers():
    with lock:
        return {
            'Jwttoken': token_data['jwttoken'],
            'Accesstoken': token_data['accesstoken']
        }

# ---------------------------- Health Endpoint -----------------------------------#

def test_health():
    """
    Test /health endpoint to ensure service is running.
    """
    get_response = requests.get(f'{BASE_URL}/health')
    json_get_data = get_response.json()

    assert get_response.status_code == 200, "Health check failed"
    assert json_get_data.get('status') == "OK", "Unexpected health check response"

# ------------------------------ Public READ Endpoints------------------------------#
# Public Read
def test_log_read(auth_headers):
    """
    Test /log_read endpoint and validate response schema.

    Response:
    {"payload": {
            "data": [
                [
                    "1734177675",
                    "{\"Log\": \"<p>this is test 1 updated one</p>\", \"Date\": \"2024-12-14T17:31\", \"Type\": \"Update\"}"
                ],
                [
                    "1734177699",
                    "{\"Log\": \"<p>this is test 2</p>\", \"Date\": \"2024-12-14T17:31\", \"Type\": \"Release\"}"
                ],
            ]
        },"status": "SUCCESS"}
    """
    # get_response = requests.get(f'{BASE_URL}/log_read')
    get_response = requests.get(f'{BASE_URL}/log_read',
                            headers=auth_headers
                            )
    json_get_data = get_response.json()
    print(f"PUBLIC READ:{json_get_data}")
    print('\n')
    assert get_response.status_code == 200, "Failed to read logs"
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    try:
        response = Response(**json_get_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")

    # Validate Payload structure
    json_payload = json_get_data.get('payload', {})
    try:
        payload_valid = Payload(**json_payload)
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")

    # Validate first log entry if available
    if json_payload.get('data'):
        json_data_string = json_payload['data'][0][1]
        try:
            dict_obj = json.loads(json_data_string)
            log_entry = LogEntry(**dict_obj)
        except (json.JSONDecodeError, ValidationError) as e:
            pytest.fail(f"Log entry parsing or validation error: {e}")

#------------------------------------ Read Endpoints --------------------------------------------------------#
# Crud Logs Read
def test_crud_logs_read(auth_headers):
    """
    Test /crud_logs endpoint, validate data structure including email and log entry.

    Response:
    {'payload': {
            'data': [
            ['1734177675', 'samudragupta201@gmail.com', 
                '{"Log": "<p>this is test 1 updated one</p>", 
                  "Date": "2024-12-14T17:31", 
                  "Type": "Update"}'], 
            ['1734177699', 'samudragupta201@gmail.com', 
                '{"Log": "<p>this is test 2</p>", 
                  "Date": "2024-12-14T17:31", 
                  "Type": "Release"}']]
            }, 'status': 'SUCCESS'}
    """
    get_response = requests.get(f'{BASE_URL}/crud_logs',
                                headers=auth_headers
                                )
    json_get_data = get_response.json()
    print(f"CRUD LOGS READ:{json_get_data}")
    print('\n')
    assert get_response.status_code == 200, "Failed to read CRUD logs"
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    try:
        response = Response(**json_get_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")

    # Validate Payload structure
    json_payload = json_get_data.get('payload', {})
    try:
        payload_valid = Payload(**json_payload)
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")

    # Validate first record if available
    if json_payload.get('data'):
        record = json_payload['data'][0]
        try:
            log_data = json.loads(record[2])
            log_entry = LogEntry(**log_data)
            email = record[1]
            email_valid = EmailValid(email=email)
        except (json.JSONDecodeError, ValidationError) as e:
            pytest.fail(f"Nested data validation error: {e}")


# ----------------------------------- CREATE / UPDATE / DELETE -------------------------------------#
# Func to get latest TS
def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest log timestamp (ts) from /crud_logs.
    """
    response = requests.get(f'{BASE_URL}/crud_logs',
                                headers=auth_headers
                            )
    assert response.status_code == 200, "Failed to fetch logs"
    
    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])

    assert data_list, "No log entries found"
    
    latest_entry = data_list[-1]  # Assuming last item is the latest
    ts = latest_entry[0]  # ts is the first element
    return ts

# Fixture / Function for create
@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Fixture to create a log and return its timestamp for further operations.
    """
    input_data = {
        "data": {
            "Date": "14-04-2025T12:25",
            "Log": "version 1.24.8",
            "Type": "Release"
        }
    }

    post_response = requests.post(f'{BASE_URL}/crud_logs', 
                                  json=input_data,
                                  headers=auth_headers
                                  )
    json_create_data = post_response.json()

    print(f'Input given:{input_data}')
    print(f'Create Status:{json_create_data}')
    print('\n')
    
    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Create log response validation error: {e}")

    return get_latest_ts(auth_headers)

# Crud Logs Create
def test_create(created_log_ts):
    """
    Test that log was successfully created.
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log with ts: {created_log_ts}")
    print('\n')

# Crud Logs Update
def test_update(created_log_ts, auth_headers):
    """
    Test updating an existing log using its timestamp.
    """
    input_data = {
        "data": {
            "Date": "15-04-2025T10:00",
            "Log": "version 1.24.9 - Updated",
            "Type": "Improvement"
        },
        "ts": created_log_ts
    }

    update_response = requests.put(f'{BASE_URL}/crud_logs',
                    json=input_data,
                    headers=auth_headers
                    )
    json_update_data = update_response.json()

    assert update_response.status_code == 200

    print(f"Updated TS:{created_log_ts}")
    print(f'Update Status:{json_update_data}')
    print('\n')

    try:
        response = Response(**json_update_data)
        assert response.status == "SUCCESS"
    except ValidationError as e:
        pytest.fail(f"Update response validation error: {e}")

# Crud Logs Delete
def test_delete(created_log_ts, auth_headers):
    """
    Test deleting a log using its timestamp.
    """
    delete_response = requests.delete(f'{BASE_URL}/crud_logs', 
                                      json={"ts": created_log_ts},
                                      headers=auth_headers
                                      )
    delete_json_data = delete_response.json()

    assert delete_response.status_code == 200

    print(f"Deleted TS:{created_log_ts}")
    print(f'Delete Status:{delete_json_data}')

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation error: {e}")
