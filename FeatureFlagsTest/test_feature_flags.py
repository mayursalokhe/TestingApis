import requests
import pytest
from pydantic import ValidationError, BaseModel
from typing import List, Dict
import pyotp
import threading
import time 
import jwt
import configparser

config = configparser.ConfigParser()
config.read("config.ini")

AUTH_URL = "https://beta.tradefinder.in/api_be/auth_internal/"
BASE_URL = "https://beta.tradefinder.in/api_be/feature_flag"

#--------------------------------------------- Pydantic Models ----------------------------------------------#

class Payload(BaseModel):
    data: Dict[str, Dict]
 
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
    Test for health of trading journal
    """

    response = requests.get(f'{BASE_URL}/health')
    response_json = response.json()

    print(f'\nHealth Status: {response_json}\n')

    assert response.status_code == 200, "Health check failed"
    assert response_json.get('status') == "OK", "Unexpected health check response"

#---------------------------------------- Read --------------------------------------------#

def test_feature_flags_read(auth_headers):
    """
    Test for feature flags read endpoint
    Response Example:
    {'payload': {'data': {
        'calculator': 
            {'message': '', 'page_hide': 'Show'}, 
        'calendar': 
            {'message': '', 'page_hide': 'Show'}, 
        'faq-videos': 
            {'message': '', 'page_hide': 'Show'}, 
        'feedback': 
            {'message': '', 'page_hide': 'Show'}, 
        'fii-dii-data': 
            {'message': '', 'page_hide': 'Show'}, 
        'games': 
            {'message': '', 'page_hide': 'Show'},
        'payments': 
            {'message': '', 'page_hide': 'Hide'}, 
        'index-mover': 
            {'message': '', 'page_hide': 'Show'}}
        }, 
        'status': 'SUCCESS'}

    """
    print("\nRunning feature flags Read Test...\n")

    response = requests.get(f'{BASE_URL}/feature_read', headers=auth_headers)
    response_json = response.json()

    print(f'\nfeature flags Read JSON: {response_json}\n')

    assert response.status_code == 200, "Failed to read feature flags"
    assert isinstance(response_json['payload'], dict)
    assert isinstance(response_json['payload']['data'], dict)

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

#------------------------------------------ Update ----------------------------------------#

def test_feature_flags_update(auth_headers):
    """
    Test for feature flags update endpoint
    """
    input_json = {"profit": {"message":"Profit Hide", "page_hide": "Hide"}}

    print(f'\nRunning feature flags Update Test...\n')

    update_response = requests.put(f'{BASE_URL}/feature_update', headers=auth_headers, json=input_json)
    update_response_json = update_response.json()

    print(f'\nfeature flags Update JSON: {update_response_json}\n')

    try:
        response_model = Response(**update_response_json)
        assert response_model.status == 'SUCCESS'
    except ValidationError as e:
        pytest.fail(f"\nUpdate log response validation error: {e}\n")

#--------------------------------------------- Helper Func Test for read after update -----------------------#

# def test_feature_flags_read_after_update(auth_headers):
#     """
#     Test for feature flags read after update endpoint
#     """

#     print(f'\nRunning fature flags read after update...\n')

#     response = requests.get(f'{BASE_URL}/feature_read', headers=auth_headers)
#     response_json = response.json()

#     print(f'\nfeature flags Read JSON:{response_json}\n')


