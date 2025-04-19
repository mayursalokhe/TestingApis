import requests
import pytest
import json
from pydantic import ValidationError, BaseModel
from typing import List
import pyotp
import threading
import time
import jwt
import configparser

config = configparser.ConfigParser()
config.read("config.ini")

AUTH_URL = "https://beta.tradefinder.in/api_be/auth_internal/"
BASE_URL = "https://beta.tradefinder.in/api_be/admin/log_updates"

# ------------------------------------ Pydantic Models -----------------------------------#
# {'payload': {'data': [ ['1734178729', '{"Log": "<p>dfgdsfsdfgsd</p>", "Date": "2024-12-04T17:48", "Type": "Update"}'], ['1734178736', '{"Log": "<p>dfgghfhjjuuy</p>", "Date": "2024-12-27T17:48", "Type": "Update"}'], ['1744177050', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744177299', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744177329', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744180886', '{"Log": "version 1.24.8", "Date": "09-04-2025T11:30", "Type": "updated"}'], ['1744632825', '{"Log": "version 1.24.9 - Updated", "Date": "15-04-2025T10:00", "Type": "Improvement"}'], ['1744705177', '{"Log": "version 1.24.8", "Date": "14-04-2025T12:25", "Type": "Release"}']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]

# response staus
class Response(BaseModel):
    status: str

# --------------------------------- Token Management ------------------------------------ #
# # SECRET_KEY = pyotp.random_base32()
SECRET_KEY = config['ACCESS TOKEN']['SECRET_KEY']

lock = threading.Lock()

token_data = {
    'jwttoken': None,
    'accesstoken': None
}

def is_token_expired(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get("exp")
        return time.time() > exp if exp else True
    except Exception as e:
        print(f"\nToken decode error: {e}\n")
        return True
    
# JWT TOKEN Func
def get_jwttoken():
    try:
        response = requests.get(f'{AUTH_URL}/bot_auth_internal',
                                headers={'Authorization':config['JWT TOKEN']['AUTHORIZATION'], 'User-Agent': config['JWT TOKEN']['USER_AGENT']}
                                )
        # return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijg1MGVlNGU0MWMzZjExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0OTcxOTU4LjkzNDcwNSwiZXhwIjoxNzQ0OTgyNzU4LjkzNDcwNSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.eWhTmvlOfPSnbEWmUj2tsvnCr6zxZXnoz1Rg7IK679o" 
        print(f'\nJwttoken:{response.text}\n')
        return response.text
    except Exception as e:
        print(f'Auth Internal JWTTOKEN Error:{e}')

# ACCESS TOKEN Func
def get_accesstoken():
    access_token = pyotp.TOTP(SECRET_KEY, interval=30).now()
    print(f'\nAccess Token:{access_token}\n')
    return access_token

def refresh_tokens():
    while True:
        with lock:
            if token_data['jwttoken'] is None or is_token_expired(token_data['jwttoken']):
                print("\nRefreshing JWT Token...\n")
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

# ----------------------------- Health Check ----------------------------- #

def test_health():
    """
    Ensure /health endpoint is operational.
    """
    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    assert response.status_code == 200
    assert response_json.get('status') == "OK"

# ---------------------------- Public Read API --------------------------- #

def test_log_read(auth_headers):
    """
    Test /log_read endpoint and validate response schema.

    Response Example:
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
    response = requests.get(f'{BASE_URL}/log_read', headers=auth_headers)
    response_json = response.json()

    print(f"\nPUBLIC READ:\n{response_json}\n")

    assert response.status_code == 200
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation failed: {e}")
    
    # Validate Payload structure
    try:
        payload_model = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")

# ----------------------------- Admin Read API ---------------------------- #

def test_crud_logs_read(auth_headers):
    """
    Validate CRUD logs read structure, email & log body.
    """
    response = requests.get(f'{BASE_URL}/crud_logs', headers=auth_headers)
    response_json = response.json()

    print(f"\nCRUD LOGS READ:\n{response_json}\n")

    assert response.status_code == 200
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation failed: {e}")
        
    # Validate Payload structure
    try:
        payload_model = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")

# ------------------------ Create / Update / Delete ------------------------ #

def get_latest_ts(auth_headers):
    """
    Fetch latest timestamp from logs.
    """
    response = requests.get(f'{BASE_URL}/crud_logs', headers=auth_headers)
    assert response.status_code == 200

    response_json = response.json()
    data_list = response_json.get("payload", {}).get("data", [])
    assert data_list, "No logs found"
    ts = data_list[-1][0]  # Last entry assumed latest
    print(f"Latest Timestamp: {ts}\n")
    return ts

@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Create a log and return timestamp.
    """
    input_data = {
        "data": {
            "Date": "14-04-2025T12:25",
            "Log": "version 1.24.8",
            "Type": "Release"
        }
    }

    print(f"\nCreating new log with:\n{input_data}\n")

    response = requests.post(f'{BASE_URL}/crud_logs', json=input_data, headers=auth_headers)
    response_json = response.json()

    print(f"Create Response:\n{response_json}\n")

    assert response.status_code == 200

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Create validation failed: {e}")

    return get_latest_ts(auth_headers)

def test_create(created_log_ts):
    """
    Confirm creation timestamp is valid.
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log timestamp: {created_log_ts}\n")

def test_update(created_log_ts, auth_headers):
    """
    Update log by timestamp.
    """
    input_data = {
        "data": {
            "Date": "15-04-2025T10:00",
            "Log": "version 1.24.9 - Updated",
            "Type": "Improvement"
        },
        "ts": created_log_ts
    }

    response = requests.put(f'{BASE_URL}/crud_logs', json=input_data, headers=auth_headers)
    response_json = response.json()

    print(f"\nUpdated Timestamp: {created_log_ts}")
    print(f"Update Result:{response_json}\n")

    assert response.status_code == 200

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Update response validation failed: {e}")

def test_delete(created_log_ts, auth_headers):
    """
    Delete log by timestamp.
    """
    response = requests.delete(f'{BASE_URL}/crud_logs', json={"ts": created_log_ts}, headers=auth_headers)
    response_json = response.json()

    print(f"\nDeleted Timestamp: {created_log_ts}")
    print(f"Delete Result:{response_json}\n")

    assert response.status_code == 200

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation failed: {e}")
