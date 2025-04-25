import requests
import pytest
from pydantic import ValidationError, BaseModel
from typing import List
import pyotp
import threading
import time 
import jwt
from datetime import datetime
import base64
import json
import configparser

config = configparser.ConfigParser()
config.read("config.ini")

AUTH_URL = "https://beta.tradefinder.in/api_be/auth_internal/"
BASE_URL = "https://beta.tradefinder.in/api_be/journal"

#--------------------------------------------- Pydantic Models ----------------------------------------------#

# "payload": {"data": [[1745213574,"betatfbot2025@gmail.com",1729742400,1729764000,"{\"image\": \"https://tredcode-2-test.s3.amazonaws.com/GDVE8MLKZDMI.jpeg\", \"mistake\": \"Arfggaehg\", \"quantity\": 4, \"trade_id\": 0, \"exit_price\": 721, \"find_trade\": \"klp\", \"trade_type\": \"Long\", \"entry_price\": 452, \"exit_reason\": \"artggrgt\", \"entry_reason\": \"kpsrg\", \"symbol_ticker\": \"ACC\"}"]]}
class Payload(BaseModel):
    data: List[List]
 
# response status 
class Response(BaseModel):
    status: str

# inster_list read route
class instr_list_Payload(BaseModel):
    data: str

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
        #return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6Ijg1MGVlNGU0MWMzZjExZjBhMzEwMjczYTJmOGFhMGFhIiwiZW1haWwiOiJtYXl1cnNhbG9raGU5MjAxQGdtYWlsLmNvbSIsInN0YXJ0IjoxNzQ0OTcxOTU4LjkzNDcwNSwiZXhwIjoxNzQ0OTgyNzU4LjkzNDcwNSwicGxhbiI6IkRJQU1PTkQiLCJ1c2VyX3R5cGUiOiJjbGllbnQiLCJhY2Nlc3MiOiJ7XCJtYXJrZXRfcHVsc2VcIjogMSwgXCJpbnNpZGVyX3N0cmF0ZWd5XCI6IDAsIFwic2VjdG9yX3Njb3BlXCI6IDAsIFwic3dpbmdfc3BlY3RydW1cIjogMCwgXCJvcHRpb25fY2xvY2tcIjogMCwgXCJvcHRpb25fYXBleFwiOiAwLCBcInBhcnRuZXJfcHJvZ3JhbVwiOiAwfSIsImFjY291bnRfZXhwIjoiMTc3NjE5MTQwMCIsImJyb2tlciI6IiJ9.eWhTmvlOfPSnbEWmUj2tsvnCr6zxZXnoz1Rg7IK679o"  
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
    Test for health of trading journal
    """

    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    print(f'\nHealth Status: {response_json}\n')

    assert response.status_code == 200, "Health check failed"
    assert response_json.get('status') == "OK", "Unexpected health check response"

#------------------------------------- Read instr_list ------------------------------------#

def test_read_instr_list(auth_headers):
    response = requests.get(f'{BASE_URL}/instr_list', headers=auth_headers)

    assert response.status_code == 200, "Failed to fetch logs"
    
    response_json = response.json()

    print(f'\nTrading Journal read instr list (JSON): {response_json}\n')

    assert response.status_code == 200, "Failed to read logs"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], str)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"\nResponse schema validation error: {e}\n")

    # Validate Payload structure
    try:
        payload_valid = instr_list_Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"\nPayload schema validation error: {e}\n")

#-------------------------------------- Create  ---------------------------------------------#

now_start = datetime.now()
start_ts = now_start.replace(hour=15, minute=00, second=0, microsecond=0) # current date with time 15:00:00
entry_ts = start_ts.timestamp()

now_end = datetime.now()
end_ts = now_end.replace(hour=19, minute=00, second=0, microsecond=0) #current date with time 19:00:00
exit_ts = end_ts.timestamp()

date_range = {"start_time":entry_ts,"end_time":exit_ts}

# Example Base64 Image
imageBase64 = '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'

json_str = json.dumps(date_range)

# Encode to Base64
encoded_data = base64.b64encode(json_str.encode()).decode()

print(f'\nEntry Timestamp:{entry_ts}\n')
print(f'\nExit Timestamp:{exit_ts}\n')
print(f'\nEncoded data for get request:{encoded_data}\n')

# Funv to get latest timestamp
def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest log timestamp (ts)
    """
    params = {
        'data':encoded_data
    }

    response = requests.get(f'{BASE_URL}/curd_journal', headers=auth_headers, params=params)

    assert response.status_code == 200, "Failed to fetch logs"
    
    res_json = response.json()
    data_list = res_json.get("payload", {}).get("data", [])

    print(f"\nFetched data list for latest TS: {data_list}\n")

    assert data_list, "No log entries found"
    
    latest_entry = data_list[-1] # last entry is latest one
    ts = latest_entry[0]
    print(f"Latest Timestamp: {ts}\n")
    return ts

# Func for creating journal
@pytest.fixture(scope="module")
def created_log_ts(auth_headers):
    """
    Fixture to create a log entry and return its timestamp
    """
    input_data = {
        'trade_type': 'Long',
        'entry_ts': entry_ts,
        'exit_ts': exit_ts,
        'symbol_ticker':'ACC',
        "entry_price":200,
        "exit_price":300,
        "quantity":1,
        'image': imageBase64,
        "find_trade":"klp",
        "entry_reason":"entryReasonTest",
        "exit_reason":"exitReasonTest",
        "mistake":"mistake_test",
        "trade_id":0
    }

    print(f"\nCreating log entry with data: {input_data}\n")

    post_response = requests.post(f'{BASE_URL}/curd_journal',
                                  json=input_data,
                                  headers=auth_headers)

    json_create_data = post_response.json()

    print(f'\nCreate Response: {json_create_data}\n')

    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"\nCreate log response validation error: {e}\n")

    return get_latest_ts(auth_headers)

def test_create(created_log_ts):
    """
    Test for feedback api create endpoint
    """
    print(f"\nCreated log with ts: {created_log_ts}\n")

    assert created_log_ts is not None
    assert isinstance(created_log_ts, int)

#------------------------------ Read ----------------------------------------#

def test_read(auth_headers):
    """
    Test /log_read endpoint and validate response schema.

    Response Example:
    {
    'payload': {
        'data': [
        [
            1745294845,
            'betatfbot2025@gmail.com',
            1745314200,
            1745328600,
            '{"image": "", "mistake": "mistake_test", "quantity": 3, "trade_id": 3, "exit_price": 200, "find_trade": "klp", "trade_type": "Long", "entry_price": 100, "exit_reason": "exitReasonTest", "entry_reason": "entryReasonTest", "symbol_ticker": "ACC"}'
        ],
        [
            1745297149,
            'betatfbot2025@gmail.com',
            1745314200,
            1745328600,
            '{"image": "https://tredcode-2-test.s3.amazonaws.com/ZFJB2CF23PNN.Z", "mistake": "mistake_testUpdated", "quantity": 1, "exit_price": 300, "find_trade": "klp", "trade_type": "Short", "entry_price": 100, "exit_reason": "exitReasonTestUpdated", "entry_reason": "entryReasonTestUpdated", "symbol_ticker": "ACC"}'
        ]
        ]
    },
    'status': 'SUCCESS'
    }
    """
    params = {
        'data':encoded_data
    }

    response = requests.get(f'{BASE_URL}/curd_journal', headers=auth_headers, params=params)

    assert response.status_code == 200, "Failed to fetch logs"
    
    response_json = response.json()

    print(f'\nTrading Journal read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read logs"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], list)

    # Response Validation
    try:
        response_model = Response(**response_json)
        assert response_model.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"\nResponse schema validation error: {e}\n")

    # Validate Payload structure
    try:
        payload_valid = Payload(**response_json['payload'])
    except ValidationError as e:
        pytest.fail(f"\nPayload schema validation error: {e}\n")

#-------------------------------- Update -------------------------------#

def test_update(created_log_ts, auth_headers):
    input_data = {
        'trade_type': 'Short',
        'entry_ts': entry_ts,
        'exit_ts': exit_ts,
        'symbol_ticker':'ACC',
        "entry_price":100,
        "exit_price":300,
        "quantity":1,
        'image': imageBase64,
        "find_trade":"klp",
        "entry_reason":"entryReasonTestUpdated",
        "exit_reason":"exitReasonTestUpdated",
        "mistake":"mistake_testUpdated",
        "trade_id":created_log_ts
    }

    print(f"\nUpdated log entry with data: {input_data}")

    put_response = requests.put(f'{BASE_URL}/curd_journal',
                                  json=input_data,
                                  headers=auth_headers)

    put_response_json = put_response.json()

    print(f"\nUpdated Timestamp: {created_log_ts}")
    print(f'\nUpdate Response: {put_response_json}\n')

    assert put_response.status_code == 200

    try:
        response = Response(**put_response_json)
        assert response.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"\nUpdate log response validation error: {e}\n")


#--------------------------------------------- Delete --------------------------------------------#

def test_delete(created_log_ts, auth_headers):
    delete_response = requests.delete(f'{BASE_URL}/curd_journal', 
                                      json={"trade_id": created_log_ts},
                                      headers=auth_headers)
    delete_json_data = delete_response.json()
    
    print(f"\nDeleted Timestamp: {created_log_ts}")
    print(f"\nDelete Response: {delete_json_data}\n")
    
    assert delete_response.status_code == 200

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS', "API response status is not SUCCESS"
    except ValidationError as e:
        pytest.fail(f"\nDelete response validation error: {e}\n")


#---------------------------------------- Helper Test Func for reading updated data ------------------------------------------#
# def test_read_updated(auth_headers):
#     params = {
#         'data':encoded_data
#     }

#     response = requests.get(f'{BASE_URL}/curd_journal', headers=auth_headers, params=params)

#     assert response.status_code == 200, "Failed to fetch logs"
    
#     response_json = response.json()

#     print(f'\nTrading Journal read JSON: {response_json}\n')
