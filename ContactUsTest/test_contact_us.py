import requests
import pytest
from models import LogEntry, Payload, Response
import datetime
import json
from pydantic import ValidationError
import pyotp
import threading
import time 
import jwt
import openpyxl
import io

BASE_URL = "https://beta.tradefinder.in/api_be/contact_us"
SECRET_KEY = pyotp.random_base32()

lock = threading.Lock()

token_data = {
    'jwttoken': None,
    'accesstoken': None
}

# ------------------------- Token Management ------------------------- #

def is_token_expired(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get("exp")
        return time.time() > exp if exp else True
    except Exception as e:
        print(f"\nError decoding token: {e}\n")
        return True

def get_jwttoken():
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijg1MGVlNGU0MWMzZjExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0OTcxOTU4LjkzNDcwNSwiZXhwIjoxNzQ0OTgyNzU4LjkzNDcwNSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.eWhTmvlOfPSnbEWmUj2tsvnCr6zxZXnoz1Rg7IK679o"  

def get_accesstoken():
    return pyotp.TOTP(SECRET_KEY, interval=30).now()

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

# ------------------------- Health Check --------------------------- #

def test_health():
    """
    Test /health endpoint to ensure service is running.
    """
    print("\nRunning Health Check...\n")

    get_response = requests.get(f'{BASE_URL}/health')
    json_get_data = get_response.json()

    print(f"Health Status: {json_get_data}\n")

    assert get_response.status_code == 200
    assert json_get_data.get('status') == "OK"

# ------------------------- Admin Contact Read ------------------------- #

def test_contact_admin_read(auth_headers):
    """
    Test /log_read endpoint and validate response schema.

    Response:
    {
        "payload": {
            "data": [
                [
                    "1744797014",
                    "hr@gmail.com",
                    "harshada",
                    "8433544979",
                    "this is testing contact message"
                ],
                [
                    "1744796400",
                    "hr@gmail.com",
                    "harshada",
                    "8433544979",
                    "this is testing contact message"
                ],
                [
                    "1727689882",
                    "nayan@gmail.com",
                    "nayan",
                    "7894561230",
                    "This is a testing message"
                ]
            ]
        },
        "status": "SUCCESS"
    }
    """
    print("\nRunning Contact Admin Read...\n")

    get_response = requests.get(f'{BASE_URL}/admin_contact', headers=auth_headers)
    json_get_data = get_response.json()

    print(f"CONTACT ADMIN READ: {json_get_data}\n")

    assert get_response.status_code == 200
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
    print(f'Json Payload: {json_payload}\n')

    try:
        payload_valid = Payload(**json_payload)
        for item in payload_valid.data:
            assert len(item) == 5, f"Expected 5 fields but got {len(item)}: {item}"
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")

    # Validate Payload -> Data(list) -> list 
    field_names = ['ts', 'email', 'name', 'contact', 'message']
    json_payload_data_list = json_payload.get('data')

    try:
        if not json_payload_data_list:
            raise ValueError("Empty 'data' field in payload")

        inner_list = json_payload_data_list[0]

        if len(inner_list) != len(field_names):
            raise ValueError("Mismatch between fields and data")

        entry_dict = dict(zip(field_names, inner_list))

        print(f"Mapped Dict: {entry_dict}\n")

        log_entry = LogEntry(**entry_dict)
        print(f"Parsed LogEntry: {log_entry}\n")

    except ValidationError as ve:
        pytest.fail(f"Validation error: {ve}")
    except (ValueError, IndexError) as e:
        pytest.fail(f"Data mapping error: {e}")

# ------------------------- Create & Delete Contact Log ------------------------- #

def get_latest_ts(auth_headers):
    """
    Get latest timestamp from /admin_contact.
    """
    print("\nFetching latest timestamp...\n")

    response = requests.get(f'{BASE_URL}/admin_contact', headers=auth_headers)
    assert response.status_code == 200

    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])
    assert data_list, "No log entries found"

    ts = data_list[0][0] # Assuming first item is the latest
    print(f"Latest Timestamp: {ts}\n")
    return ts

@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Create a new contact log and return its timestamp.
    """
    input_data = {
        "name": "testuser",
        "email": "testuser@gmail.com",
        "contact": "1234567890",
        "message": "this is testing contact message"
    }

    print(f"\nCreating new contact log with: {input_data}\n")

    post_response = requests.post(f'{BASE_URL}/contact_us_crud',
                                  json=input_data,
                                  headers=auth_headers)

    json_create_data = post_response.json()

    print(f"Create Response: {json_create_data}\n")

    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Create log response validation error: {e}")

    return get_latest_ts(auth_headers)

def test_contact_create(created_log_ts):
    """
    Ensure log creation returns a valid timestamp.
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log with timestamp: {created_log_ts}\n")

def test_contact_delete(created_log_ts, auth_headers):
    """
    Delete the created log using timestamp.
    """
    print(f"\nDeleting contact log with timestamp: {created_log_ts}\n")

    delete_response = requests.delete(f'{BASE_URL}/admin_contact',
                                      json={"timestamp": created_log_ts},
                                      headers=auth_headers)

    delete_json_data = delete_response.json()

    print(f"Delete Response: {delete_json_data}\n")

    assert delete_response.status_code == 200

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation error: {e}")

# ------------------------- Download Excel ------------------------- #

def test_download_excel(auth_headers):
    """
    Test for downloading and validating Excel file
    """
    print("\nTesting Excel Download...\n")

    url = f'{BASE_URL}/download_excel'
    response = requests.get(url, headers=auth_headers)

    print(f"Download Status: {response.status_code}")
    print(f"Content-Type: {response.headers['Content-Type']}\n")

    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    try:
        workbook = openpyxl.load_workbook(io.BytesIO(response.content))
        sheet_names = workbook.sheetnames

        print(f"Excel file is valid. Sheets: {sheet_names}\n")

        sheet = workbook.active
        assert sheet.max_row > 1, "Not enough rows in Excel"
        assert sheet.max_column > 1, "Not enough columns in Excel"
        assert sheet.cell(row=1, column=1).value is not None, "Top-left cell is empty"

    except Exception as e:
        pytest.fail(f"Failed to open/read Excel file: {e}")

    ## Download Excel file
    # filename = 'downloaded_file.xlsx'
    # if response.status_code == 200:
    #     with open(filename, 'wb') as f:
    #         f.write(response.content)
    #     print(f"Excel file downloaded and saved as '{filename}'")
    # else:
    #     print(f"Failed to download file. Status code: {response.status_code}")