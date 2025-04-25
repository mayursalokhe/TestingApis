import requests
import pytest
from pydantic import ValidationError, BaseModel
from typing import List, Dict
import pyotp
import threading
import time 
import jwt
import configparser
from datetime import datetime

config = configparser.ConfigParser()
config.read("config.ini")

AUTH_URL = "https://beta.tradefinder.in/api_be/auth_internal/"
BASE_URL = "https://beta.tradefinder.in/api_be/fincal"

#--------------------------------------------- Pydantic Models ----------------------------------------------#

# {'payload': {'data': {'calculator': {'message': '', 'page_hide': 'Show'}, 'calendar': {'message': '', 'page_hide': 'Show'}, 'faq-videos': {'message': '', 'page_hide': 'Show'}, 'feedback': {'message': '', 'page_hide': 'Show'},  'games': {'message': '', 'page_hide': 'Show'},  'watchlist': {'message': '', 'page_hide': 'Show'}}}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]
 
# response status 
class Response(BaseModel):
    status: str

# ------------------------------------- Token Management ----------------------------------- #

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
        print(f'Jwttoken:\n{response.text}')
        return response.text
    except Exception as e:
        print(f'Auth Internal JWTTOKEN Error:{e}')


# ACCESS TOKEN Func
def get_accesstoken():
    access_token = pyotp.TOTP(SECRET_KEY, interval=30).now()
    print(f'Access Token:\n{access_token}')
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
    
#------------------------------------ Health check ----------------------------------------#

def test_health():
    """
    Test for health of financial calender
    """

    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    print(f'\nHealth Status: {response_json}\n')

    assert response.status_code == 200, "Health check failed"
    assert response_json.get('status') == "OK", "Unexpected health check response"

#------------------------------------------ Events Read -----------------------------------#

def test_events_read(auth_headers):
    """
    Test for events read of financial calender
    """

    print("\nRunning events read of financial calender Test...\n")
    
    response = requests.get(f'{BASE_URL}/events_read', headers=auth_headers)
    response_json = response.json()

    print(f'\nEvents read of financial calender Read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read events of financial calender"
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

#---------------------------------------------- CRUD Create ----------------------------------#

def get_latest_ts(auth_headers):
    """
    Get latest timestamp from /crud_fincal where the record matches specific criteria.
    """
    print("\nFetching latest timestamp...\n")

    response = requests.get(f'{BASE_URL}/crud_fincal', headers=auth_headers)
    assert response.status_code == 200, f"Request failed with status {response.status_code}"

    response_json = response.json()
    data_list = response_json.get("payload", {}).get("data", [])
    assert data_list, "No log entries found"

    # Matching criteria
    input_data = {
        "heading": "Test Holiday",
        "description": "Test Holiday",
        "symbol": "VBL",
        "sname": "VBL"
    }

    matches = [
        entry for entry in data_list
        if len(entry) >= 7 and
           entry[2] == input_data["heading"] and
           entry[3] == input_data["description"] and
           entry[5] == input_data["symbol"] and
           entry[6] == input_data["sname"]
    ]

    if not matches:
        raise AssertionError("No matching entry found for the event")

    latest_entry = max(matches, key=lambda x: x[0])  # Assuming timestamp is at index 0
    # max(matches, key=lambda x: x[0]) finds the entry with the highest (latest) timestamp.
    created_timestamp = latest_entry[0] # After finding the latest entry, this line extracts its timestamp

    print("Created Timestamp is:", created_timestamp)
    return created_timestamp

@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Create a new event log and return its timestamp.
    """
    EventDate = datetime.now()
    EventDateTime = EventDate.replace(hour=15, minute=00, second=0, microsecond=0) # current date with time 15:00:00
    dt_stamp = EventDateTime.timestamp()
    # dt_stamp = 1738348200
    print(f'Event Date Time:{dt_stamp}')

    input_data = {
        "date": int(dt_stamp),
        "heading":"Test Holiday",
        "description":"Test Holiday",
        "symbol":"VBL",
        "sname":"VBL"
    }

    print(f"\nCreating new event log with: {input_data}\n")

    response = requests.post(f'{BASE_URL}/crud_fincal',
                                  json=input_data,
                                  headers=auth_headers)

    response_json = response.json()

    print(f"Create Response: {response_json}\n")

    assert response.status_code == 200, f"POST failed with status {response.status_code}"

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"Create event log response validation error: {e}")

    return get_latest_ts(auth_headers)

def test_event_create(created_log_ts):
    """
    Ensure event creation returns a valid timestamp.
    """
    assert created_log_ts is not None, "Timestamp is None – event might not have been created properly"
    assert isinstance(created_log_ts, str) # Timestamp here is in string
    print(f"Created event log with timestamp: {created_log_ts}\n")

#------------------------------------------ CRUD Read -----------------------------------#

def test_crud_read(auth_headers):
    """
    Test for crud read of financial calender
    """

    print("\nRunning crud read of financial calender Test...\n")
    
    response = requests.get(f'{BASE_URL}/crud_fincal', headers=auth_headers)
    response_json = response.json()

    print(f'\nCrud read of financial calender Read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read crud read of financial calender"
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

#----------------------------------------- CRUD Delete -----------------------------------------#

def test_event_delete(auth_headers, created_log_ts):
    """
    Test for event delete for financial calender
    """
    response = requests.delete(f'{BASE_URL}/crud_fincal', 
                                      json={"timestamp": created_log_ts},
                                      headers=auth_headers
                                      )
    response_json = response.json()

    assert response.status_code == 200

    print(f"Deleted TS:{created_log_ts}")
    print(f'Delete Status:{response_json}')

    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"Delete response validation error: {e}")