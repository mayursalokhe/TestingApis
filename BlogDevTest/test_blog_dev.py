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
BASE_URL = "https://beta.tradefinder.in/api_be/blog"

#--------------------------------------------- Pydantic Models ----------------------------------------------#

class Payload(BaseModel):
    data: List[List]
 
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
    
#------------------------------------ Create Blog -----------------------------------------#

# Funv to get latest timestamp
def get_latest_ts(auth_headers):
    """
    Helper to fetch the latest blog timestamp (ts)
    """
    category_all = {"catg":"all"}
    json_category_str = json.dumps(category_all)
    encoded_category_all = base64.b64encode(json_category_str.encode()).decode()
    print(f'Encoded data (Category all):{encoded_category_all}')

    params = {
        'data':encoded_category_all
    }

    response = requests.get(f'{BASE_URL}/fetch_blog_list', headers=auth_headers, params=params)

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
def created_blog_ts(auth_headers):
    """
    Fixture to create a Blog entry and return its timestamp
    """
    input_data = {
        "title":"Test Blog",
        "catg":"Test Category",
        "sh_desc":"Test Description",
        "data":"This is test blog",
        "url": "https://tredcode-2-test.s3.amazonaws.com/blogs/ZKSJ6X7CI7SECDCY.png"
    }

    print(f"\nCreating Blog entry with data: {input_data}\n")

    post_response = requests.post(f'{BASE_URL}/add_blog',
                                  json=input_data,
                                  headers=auth_headers)

    json_create_data = post_response.json()

    print(f'\nCreate Response: {json_create_data}\n')

    assert post_response.status_code == 200

    try:
        response = Response(**json_create_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nCreate Blog response validation error: {e}\n")

    return get_latest_ts(auth_headers)

def test_create(created_blog_ts):
    """
    Test for Blog create endpoint
    """
    print(f"\nCreated Blog with ts: {created_blog_ts}\n")

    assert created_blog_ts is not None
    assert isinstance(created_blog_ts, str)

#-------------------------------------------------------------- Read ----------------------------------------------------#

def test_client_read(auth_headers, created_blog_ts):
    """
    Test /fetch_blog endpoint and validate response schema.

    """
    blog_id = {"blog_id": created_blog_ts}
    print(f'Blog ID:{blog_id}')
    json_str = json.dumps(blog_id)
    encoded_data = base64.b64encode(json_str.encode()).decode()
    print(f'Encoded data (blog_id/ts):{encoded_data}')

    params = {
        'data': encoded_data
    }
    response = requests.get(f'{BASE_URL}/fetch_blog', headers=auth_headers, params=params)

    assert response.status_code == 200, "Failed to fetch blog"
    
    response_json = response.json()

    print(f'\nTrading Journal read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read blog"
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

#---------------------------------- Update Blog ------------------------------------------------#

def test_update(auth_headers, created_blog_ts):
    """
    Test for update blog endpoints
    """
    input_data = {
        "blog_id":created_blog_ts,
        "title":"updated title",
        "catg":"Test Category",
        "sh_desc":"updated description",
        "data":"updated data",
        "url":"https://tredcode-2-test.s3.amazonaws.com/blogs/ZKSJ6X7CI7SECDCY.png"}

    print(f"\nUpdated blog entry with data: {input_data}")

    put_response = requests.put(f'{BASE_URL}/update_blog',
                                  json=input_data,
                                  headers=auth_headers)

    put_response_json = put_response.json()

    print(f"\nUpdated Timestamp: {created_blog_ts}")
    print(f'\nUpdate Response: {put_response_json}\n')

    assert put_response.status_code == 200

    try:
        response = Response(**put_response_json)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nUpdate blog response validation error: {e}\n")

#--------------------------------------------- Delete --------------------------------------------#

def test_delete(created_blog_ts, auth_headers):
    """
    Test for blog delete endpoints
    """
    delete_response = requests.delete(f'{BASE_URL}/delete_blog', 
                                      json={"blog_id": created_blog_ts},
                                      headers=auth_headers)
    delete_json_data = delete_response.json()
    
    print(f"\nDeleted Timestamp: {created_blog_ts}")
    print(f"\nDelete Response: {delete_json_data}\n")
    
    assert delete_response.status_code == 200

    try:
        response = Response(**delete_json_data)
        assert response.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nDelete response validation error: {e}\n")

#------------------------------------ Client Blog Read List (All Category) --------------------------------------#

def test_client_blog_read_list(auth_headers):
    """
    Test /fetch_blog_list endpoint and validate response schema.

    """
    category_all = {"catg":"all"}
    json_category_str = json.dumps(category_all)
    encoded_category_all = base64.b64encode(json_category_str.encode()).decode()
    print(f'Encoded data (Category all):{encoded_category_all}')
    
    params = {
        'data':encoded_category_all
    }

    response = requests.get(f'{BASE_URL}/fetch_blog_list', headers=auth_headers, params=params)

    assert response.status_code == 200, "Failed to fetch blogs"
    
    response_json = response.json()

    print(f'\nTrading Journal read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read blogs"
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

#------------------------------- Blog Read All ----------------------------------------------#

def test_blog_read_all(auth_headers):
    """
    Test /fetch_blog_all endpoint and validate response schema.

    """
    response = requests.get(f'{BASE_URL}/fetch_blog_all', headers=auth_headers)

    assert response.status_code == 200, "Failed to fetch blogs"
    
    response_json = response.json()

    # print(f'\nTrading Journal read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read blogs"
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
