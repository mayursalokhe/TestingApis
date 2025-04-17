import requests
import pytest
from models import Response, Payload, LogEntry, LogPublicEntry
from pydantic import ValidationError
import pyotp
import threading
import time 
import jwt


BASE_URL = "https://beta.tradefinder.in/api_be/admin/signal"

lock = threading.Lock()

token_data = {
    'jwttoken': None,
    # 'accesstoken': None
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
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImIxNjIyYzE2MWIzZDExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0ODYxMjIzLjE0Mzk2OSwiZXhwIjoxNzQ0ODcyMDIzLjE0Mzk2OSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.syt2jCitS_8zvGq4OeHfx1FB4q5XayMbmYREN0IFgA4"

def refresh_tokens():
    while True:
        with lock:
            if token_data['jwttoken'] is None or is_token_expired(token_data['jwttoken']):
                print("Refreshing JWT Token")
                token_data['jwttoken'] = get_jwttoken()
            # token_data['accesstoken'] = get_accesstoken()
        time.sleep(30)

token_refresher = threading.Thread(target=refresh_tokens, daemon=True)
token_refresher.start()

@pytest.fixture(scope="module")
def auth_headers():
    with lock:
        return {
            'Jwttoken': token_data['jwttoken'],
            # 'Accesstoken': token_data['accesstoken']
        }
    
def test_health():
    """
    Test /health endpoint to ensure service is running.
    """
    get_response = requests.get(f'{BASE_URL}/health')
    json_get_data = get_response.json()

    assert get_response.status_code == 200, "Health check failed"
    assert json_get_data.get('status') == "OK", "Unexpected health check response"


#------------------------------------------ Chat Management Public Read ----------------------------------------#

def test_public_read(auth_headers):
    """
    Test chat management public read endpoint and validate response schema.
    Response:
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
    get_response = requests.get(f'{BASE_URL}/user_read',
                                headers=auth_headers)
    json_get_data = get_response.json()
    print(f"Chat management public read: {json_get_data}")
    print('\n')

    assert get_response.status_code == 200, "Failed to read logs"
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    # Response Validation
    try:
        response = Response(**json_get_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")
    
    # Validate Payload structure
    json_payload = json_get_data.get('payload', {})
    print(f'Json Payload:{json_payload}')
    try:
        payload_valid = Payload(**json_payload)
        for item in payload_valid.data:
            assert len(item) == 3, f"Expected length 3 but got {len(item)} for item: {item}"
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")


    # Validate Payload -> Data(list) -> list 
    field_names = ['ts', 'url', 'text']

    json_payload_data_list = json_payload.get('data')

    try:
        if not json_payload_data_list:
            raise ValueError("Missing or empty 'data' field in JSON payload")

        inner_list = json_payload_data_list[0]

        if len(inner_list) != len(field_names):
            raise ValueError("Field count mismatch between data and expected model fields")

        entry_dict = dict(zip(field_names, inner_list))
        print("Mapped dict:", entry_dict)
        print('\n')

        log_entry = LogPublicEntry(**entry_dict)
        print("Parsed LogPublicEntry:", log_entry)
        print('\n')

    except ValidationError as ve:
        pytest.fail(f"Validation error: {ve}")

    except (ValueError, IndexError) as e:
        pytest.fail(f"Data mapping error: {e}")

#------------------------------------------------------- Chat Management Read -------------------------------------------------#

def test_read(auth_headers):
    """
    Test chat management public read endpoint and validate response schema.
    Response:
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
    get_response = requests.get(f'{BASE_URL}/crud_chats',
                                headers=auth_headers)
    json_get_data = get_response.json()
    print(f"Chat management read: {json_get_data}")
    print('\n')

    assert get_response.status_code == 200, "Failed to read logs"
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    # Response Validation
    try:
        response = Response(**json_get_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Response schema validation error: {e}")
    
    # Validate Payload structure
    json_payload = json_get_data.get('payload', {})
    print(f'Json Payload:{json_payload}')
    try:
        payload_valid = Payload(**json_payload)
        for item in payload_valid.data:
            assert len(item) == 4, f"Expected length 4 but got {len(item)} for item: {item}"
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")

    # Validate Payload -> Data(list) -> list 
    field_names = ['ts', 'email', 'url', 'text']

    json_payload_data_list = json_payload.get('data')

    try:
        if not json_payload_data_list:
            raise ValueError("Missing or empty 'data' field in JSON payload")

        inner_list = json_payload_data_list[0]

        if len(inner_list) != len(field_names):
            raise ValueError("Field count mismatch between data and expected model fields")

        entry_dict = dict(zip(field_names, inner_list))
        print("Mapped dict:", entry_dict)
        print('\n')

        log_entry = LogEntry(**entry_dict)
        print("Parsed LogEntry:", log_entry)
        print('\n')

    except ValidationError as ve:
        pytest.fail(f"Validation error: {ve}")

    except (ValueError, IndexError) as e:
        pytest.fail(f"Data mapping error: {e}")

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
    
    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])

    assert data_list, "No log entries found"
    
    latest_entry = data_list[0]  # Assuming first item is the latest
    ts = latest_entry[0]  # ts is the first element
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

    post_response = requests.post(f'{BASE_URL}/crud_chats', 
                                  json=input_data,
                                  headers=auth_headers
                                  )
    json_create_data = post_response.json()

    print(f'Input given:{input_data}')
    print('\n')
    print(f'Create Status:{json_create_data}')
    print('\n')
    
    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Create log response validation error: {e}")

    return get_latest_ts(auth_headers)

def test_create(created_log_ts):
    """
    Test for chat management create endpoint
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log with ts: {created_log_ts}")
    print('\n')

#------------------------------------------------ Chat Management Delete -----------------------------------------------------#

def test_delete(created_log_ts, auth_headers):
    """
    Test deleting a chat entry using its timestamp.
    """
    delete_response = requests.delete(f'{BASE_URL}/crud_chats', 
                                      json={"timestamp": created_log_ts},
                                      headers=auth_headers
                                      )
    delete_json_data = delete_response.json()

    assert delete_response.status_code == 200

    print(f"Deleted TS:{created_log_ts}")
    print(f'Delete Status:{delete_json_data}')
    print('\n')

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation error: {e}")
