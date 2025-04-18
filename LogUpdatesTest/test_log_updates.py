import requests
import pytest
from models import Payload, LogEntry, Response, EmailValid
import json
from pydantic import ValidationError
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

# --------------------------- Token Management --------------------------- #

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
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijg1MGVlNGU0MWMzZjExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0OTcxOTU4LjkzNDcwNSwiZXhwIjoxNzQ0OTgyNzU4LjkzNDcwNSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.eWhTmvlOfPSnbEWmUj2tsvnCr6zxZXnoz1Rg7IK679o" 

# ACCESS TOKEN Func
def get_accesstoken():
    return pyotp.TOTP(SECRET_KEY, interval=30).now()

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
    data = response.json()

    assert response.status_code == 200
    assert data.get('status') == "OK"

# ---------------------------- Public Read API --------------------------- #

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
    response = requests.get(f'{BASE_URL}/log_read', headers=auth_headers)
    data = response.json()

    print(f"\nPUBLIC READ:\n{data}\n")

    assert response.status_code == 200
    assert isinstance(data['payload'], dict)
    assert isinstance(data['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**data)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation failed: {e}")
    
    # Validate Payload structure
    try:
        payload_model = Payload(**data['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")
    
    # Validate Payload -> Data(list) -> list
    if data['payload']['data']:
        log_data_str = data['payload']['data'][0][1]
        try:
            log_dict = json.loads(log_data_str)
            log_entry = LogEntry(**log_dict)
            print("Validated Public Log Entry:", log_entry)
        except Exception as e:
            pytest.fail(f"Log parsing failed: {e}")

# ----------------------------- Admin Read API ---------------------------- #

def test_crud_logs_read(auth_headers):
    """
    Validate CRUD logs read structure, email & log body.
    """
    response = requests.get(f'{BASE_URL}/crud_logs', headers=auth_headers)
    data = response.json()

    print(f"\nCRUD LOGS READ:\n{data}\n")

    assert response.status_code == 200
    assert isinstance(data['payload'], dict)
    assert isinstance(data['payload']['data'], list)

    try:
        response_model = Response(**data)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation failed: {e}")

    try:
        payload_model = Payload(**data['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")

    if data['payload']['data']:
        record = data['payload']['data'][0]
        try:
            if len(record) < 3:
                raise ValueError("Insufficient fields in record")

            email = record[1]
            log_data = json.loads(record[2])
            email_valid = EmailValid(email=email)
            log_entry = LogEntry(**log_data)

            print("Validated Email:", email_valid)
            print("Validated Log Entry:", log_entry)

        except Exception as e:
            pytest.fail(f"Record validation failed: {e}")

# ------------------------ Create / Update / Delete ------------------------ #

def get_latest_ts(auth_headers):
    """
    Fetch latest timestamp from logs.
    """
    response = requests.get(f'{BASE_URL}/crud_logs', headers=auth_headers)
    assert response.status_code == 200

    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])
    assert data_list, "No logs found"

    return data_list[-1][0]  # Last entry assumed latest

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

    print(f"\nCreating Log:\n{input_data}\n")

    response = requests.post(f'{BASE_URL}/crud_logs', json=input_data, headers=auth_headers)
    result = response.json()

    print(f"Create Result:\n{result}\n")

    assert response.status_code == 200

    try:
        resp = Response(**result)
        assert resp.status == 'SUCCESS'
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
    data = response.json()

    print(f"\nUpdated Timestamp: {created_log_ts}")
    print(f"Update Result:\n{data}\n")

    assert response.status_code == 200

    try:
        resp = Response(**data)
        assert resp.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Update response validation failed: {e}")

def test_delete(created_log_ts, auth_headers):
    """
    Delete log by timestamp.
    """
    response = requests.delete(f'{BASE_URL}/crud_logs', json={"ts": created_log_ts}, headers=auth_headers)
    data = response.json()

    print(f"\nDeleted Timestamp: {created_log_ts}")
    print(f"Delete Result:\n{data}\n")

    assert response.status_code == 200

    try:
        resp = Response(**data)
        assert resp.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation failed: {e}")
