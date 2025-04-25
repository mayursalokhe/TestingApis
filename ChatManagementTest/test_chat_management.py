import requests
import pytest
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
BASE_URL = "https://beta.tradefinder.in/api_be/admin/signal"

#------------------------------------------------ Pydantic Models ----------------------------------------------#
#  {'payload': {'data': [['1744868900', '', 'kfcalulb'], ['1738305181', '', '<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]
 
# response status 
class Response(BaseModel):
    status: str

#----------------------------------------------- Token Management ----------------------------------------------#

# SECRET_KEY = pyotp.random_base32()
SECRET_KEY = config['ACCESS TOKEN']['SECRET_KEY']

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

# Refresh Token Func
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

#----------------------------------------------- Health --------------------------------------------#

def test_health():
    """
    Test /health endpoint to ensure service is running.
    """
    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    assert response.status_code == 200, "Health check failed"
    assert response_json.get('status') == "OK", "Unexpected health check response"


#------------------------------------------ Chat Management Public Read ----------------------------------------#

def test_public_read(auth_headers):
    """
    Test chat management public read endpoint and validate response schema.
    Response Example:
    {
        "payload": {
            "data": [
                [
                    "1744868900",
                    "",
                    "kfcalulb"
                ],
                [
                    "1738305181",
                    "",
                    "<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>"
                ]
            ]
        },
        "status": "SUCCESS"
    }
    """
    response = requests.get(f'{BASE_URL}/user_read',
                                headers=auth_headers
                                )
    response_json = response.json()
    print(f"Chat management public read: {response_json}\n")

    assert response.status_code == 200, "Failed to read logs"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")
    
    # Validate Payload structure
    try:
        payload_model = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")

#------------------------------------------------------- Chat Management Read -------------------------------------------------#

def test_read(auth_headers):
    """
    Test chat management public read endpoint and validate response schema.
    Response Example:
    {
        "payload": {
            "data": [
                [
                    "1744868900",
                    "harshada@gmail.com",
                    "",
                    "kfcalulb"
                ],
                [
                    "1738305181",
                    "dknaix@gmail.com",
                    "",
                    "<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>"
                ]
            ]
        },
        "status": "SUCCESS"
    }
    """
    response = requests.get(f'{BASE_URL}/crud_chats',
                                headers=auth_headers)
    response_json = response.json()
    print(f"Chat management read: {response_json}\n")

    assert response.status_code == 200, "Failed to read logs"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")
    
    # Validate Payload structure
    try:
        payload_model = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"Payload schema validation failed: {e}")


#-------------------------------------------------------- Chat Management Create -----------------------------------------#

# Func to get latest TS
def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest log timestamp (ts) from /crud_chats.
    """
    response = requests.get(f'{BASE_URL}/crud_chats',
                                headers=auth_headers
                            )
    assert response.status_code == 200, "Failed to fetch logs"
    
    response_json = response.json()
    data_list = response_json.get("payload", {}).get("data", [])

    assert data_list, "No log entries found"
    
    latest_entry = data_list[0]  # Assuming first item is the latest
    ts = latest_entry[0]  # ts is the first element
    print(f"Latest Timestamp: {ts}\n")
    return ts

# Fixture / Function for create
@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Fixture to create a log entry and return its timestamp for further operations.
    """
    input_data = {
        "url": "testurl",
        "text": "text message"
    }

    response = requests.post(f'{BASE_URL}/crud_chats', 
                                  json=input_data,
                                  headers=auth_headers
                                  )
    response_json = response.json()

    print(f"\nCreating new chat log with: {input_data}\n")
    print(f'Create Status:{response_json}\n')
    
    assert response.status_code == 200

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"validation error while creating log entry: {e}")

    return get_latest_ts(auth_headers)

def test_create(created_log_ts):
    """
    Test for chat management create endpoint
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log with ts: {created_log_ts}\n")

#------------------------------------------------ Chat Management Delete -----------------------------------------------------#

def test_delete(created_log_ts, auth_headers):
    """
    Test deleting a chat entry using its timestamp.
    """
    response = requests.delete(f'{BASE_URL}/crud_chats', 
                                      json={"timestamp": created_log_ts},
                                      headers=auth_headers
                                      )
    response_json = response.json()

    assert response.status_code == 200

    print(f"Deleted TS:{created_log_ts}")
    print(f'Delete Status:{response_json}')

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"Delete response validation error: {e}")
