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
BASE_URL = "https://beta.tradefinder.in/api_be/admin/feedback"

#---------------------------------- Pydantic Models ----------------------------#

# .{'payload': {'data': [['1744949857', 'ex@gmail.com', 'mayur', '1234567890', 'Market Pulse', '', 'good'], ['1744949333', 'h@gmail.com', 'harshada', '917854623564', 'Other', '', 'good'], ['1740422237', 'dknaix@gmail.com', "<script>alert('XSS Attack!');</script>", '9876543100', 'Other', '', "<script>alert('XSS Attack!');</script>"], ['1738238501', 'dknaix@gmail.com', 'asdas  sdfg sdfh shg', '9876543210', 'Insider Strategy', '', 'asd gs d sdfh ']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]
 
# response status 
class Response(BaseModel):
    status: str
# ----------------------------- Token Management --------------------------- #

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
        print(f"\nError decoding token: {e}\n")
        return True

# JWT Token Func
def get_jwttoken():
    try:
        response = requests.get(f'{AUTH_URL}/bot_auth_internal',
                                headers={'Authorization':config['JWT TOKEN']['AUTHORIZATION'], 'User-Agent': config['JWT TOKEN']['USER_AGENT']}
                                )
        #return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijg1MGVlNGU0MWMzZjExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0OTcxOTU4LjkzNDcwNSwiZXhwIjoxNzQ0OTgyNzU4LjkzNDcwNSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.eWhTmvlOfPSnbEWmUj2tsvnCr6zxZXnoz1Rg7IK679o"  
        print(f'Jwttoken:{response.text}')
        return response.text
    except Exception as e:
        print(f'Auth Internal JWTTOKEN Error:{e}')


# ACCESS TOKEN Func
def get_accesstoken():
    access_token = pyotp.TOTP(SECRET_KEY, interval=30).now()
    print(f'Access Token:{access_token}')
    return access_token

# Refresh Token Func
def refresh_tokens():
    while True:
        with lock:
            if token_data['jwttoken'] is None or is_token_expired(token_data['jwttoken']):
                print("\nRefreshing JWT Token\n")
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

# -------------------------- Health Check ---------------------------- #

def test_health():
    """
    Test for health of feedback api
    """
    print("\nRunning Health Check...\n")

    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    print(f'\nHealth Status: {response_json}\n')

    assert response.status_code == 200, "Health check failed"
    assert response_json.get('status') == "OK", "Unexpected health check response"

# ---------------------------- Admin Feedback Read ---------------------------- #

def test_admin_feedback_read(auth_headers):
    """
    Test for admin feedback read endpoint
    """
    print("\nRunning Admin Feedback Read Test...\n")

    response = requests.get(f'{BASE_URL}/admin_feedback', headers=auth_headers)
    response_json = response.json()

    print(f'\nAdmin feedback read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read logs"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nResponse schema validation error: {e}\n")

    # Validate Payload structure
    try:
        payload_valid = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"\nPayload schema validation error: {e}\n")


# ---------------------------- Admin Feedback Create ---------------------------- #

def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest log timestamp (ts)
    """
    response = requests.get(f'{BASE_URL}/admin_feedback', headers=auth_headers)

    assert response.status_code == 200, "Failed to fetch logs"
    
    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])

    print(f"\nFetched data list for latest TS: {data_list}\n")

    assert data_list, "No log entries found"
    
    latest_entry = data_list[0]
    ts = latest_entry[0]
    print(f"Latest Timestamp: {ts}\n")
    return ts

@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Fixture to create a log entry and return its timestamp
    """
    input_data = {
        'email': 'testuser@example.com',
        'name': 'testuser',
        'whatsapp': '9123456789',
        'category': 'Sector Scope',
        'image': 'base64str',
        'feedback': 'good'
    }

    print(f"\nCreating log entry with data: {input_data}\n")

    post_response = requests.post(f'{BASE_URL}/feedback_create',
                                  json=input_data,
                                  headers=auth_headers)

    json_create_data = post_response.json()

    print(f'\nCreate Response: {json_create_data}\n')

    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nCreate log response validation error: {e}\n")

    return get_latest_ts(auth_headers)

def test_create(created_log_ts):
    """
    Test for feedback api create endpoint
    """
    print(f"\nCreated log with ts: {created_log_ts}\n")

    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)

# ---------------------------- Admin Feedback Delete ---------------------------- #

def test_delete(created_log_ts, auth_headers):
    """
    Test deleting admin feedback entry using its timestamp.
    """
    print(f"\nAttempting to delete log entry with ts: {created_log_ts}\n")

    delete_response = requests.delete(f'{BASE_URL}/admin_feedback', 
                                      json={"timestamp": created_log_ts},
                                      headers=auth_headers)

    delete_json_data = delete_response.json()

    print(f"\nDelete Response: {delete_json_data}\n")

    assert delete_response.status_code == 200

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nDelete response validation error: {e}\n")
