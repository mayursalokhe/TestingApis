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
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImIxNjIyYzE2MWIzZDExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0ODYxMjIzLjE0Mzk2OSwiZXhwIjoxNzQ0ODg2NDU1LjA5NTI2MywicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.OoYAl_4K6QQ-jAQTjt7KaAGtSIDVJO8rxDGtD3YLh6g"

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

#------------------------------------------------------ Contact Admin Read -----------------------------------------------------#

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
    get_response = requests.get(f'{BASE_URL}/admin_contact',
                                headers=auth_headers)
    json_get_data = get_response.json()
    print(f"CONTACT ADMIN READ:{json_get_data}")
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
            assert len(item) == 5, f"Expected length 5 but got {len(item)} for item: {item}"
    except ValidationError as e:
        pytest.fail(f"Payload schema validation error: {e}")

    # Validate Payload -> Data(list) -> list 
    field_names = ['ts', 'email', 'name', 'contact', 'message']

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

#--------------------------------------------------- Contact Admin Create | Delete ------------------------------------------------#     

# Func to get latest TS
def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest log timestamp (ts) from /admin_contact.
    """
    response = requests.get(f'{BASE_URL}/admin_contact',
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
    Fixture to create a log and return its timestamp for further operations.
    """
    input_data = {
        "name":"testuser",
        "email":"testuser@gmail.com",
        "contact":"1234567890",
        "message":"this is testing contact message"
    }

    post_response = requests.post(f'{BASE_URL}/contact_us_crud', 
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

# Crud Logs Create
def test_contact_create(created_log_ts):
    """
    Test for contact create endpoint.
    """
    assert created_log_ts is not None
    assert isinstance(created_log_ts, str)
    print(f"Created log with ts: {created_log_ts}")
    print('\n')

# Crud Logs Delete
def test_contact_delete(created_log_ts, auth_headers):
    """
    Test deleting contact log using its timestamp.
    """
    delete_response = requests.delete(f'{BASE_URL}/admin_contact', 
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

#-------------------------------------------------- Test Download Excel -------------------------------------------------------#
 
# https://beta.tradefinder.in/api_be/contact_us/download_excel
def test_download_excel(auth_headers):
    """
    Test for downloading and validating Excel file
    """

    url = f'{BASE_URL}/download_excel'
    response = requests.get(url, headers=auth_headers)

    print(f"Download Excel Status: {response.status_code}")
    print(f"Download Excel Content-Type: {response.headers['Content-Type']}")

    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

    # Excel file validation
    try:
        workbook = openpyxl.load_workbook(io.BytesIO(response.content))
        sheet_names = workbook.sheetnames
        print(f"Sheet Names in Excel file: {sheet_names}")
        print(f"Excel file is valid. Sheets: {sheet_names}")

        sheet = workbook.active
        assert sheet.max_row > 1, f"Expected more than 1 row, found {sheet.max_row}"
        assert sheet.max_column > 1, f"Expected more than 1 column, found {sheet.max_column}"
        assert sheet.cell(row=1, column=1).value is not None, "Top-left cell is empty"

    except Exception as e:
        pytest.fail(f"Failed to open/read Excel file: {e}")
 
    # Download Excel file
    # filename = 'downloaded_file.xlsx'
    # if response.status_code == 200:
    #     with open(filename, 'wb') as f:
    #         f.write(response.content)
    #     print(f"Excel file downloaded and saved as '{filename}'")
    # else:
    #     print(f"Failed to download file. Status code: {response.status_code}")