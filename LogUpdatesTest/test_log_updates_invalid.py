import requests

BASE_URL = "https://beta.tradefinder.in/api_be/admin/log_updates"

def test_invalid_url():
    """
    Test an invalid URL to ensure proper error handling by the API.
    """
    get_response = requests.get(f'{BASE_URL}/invalid')
    json_get_data = get_response.json()
    
    print('\n')
    print(f"Test INVALID URL: {get_response.text}")

    assert get_response.status_code != 200, "Invalid URL unexpectedly returned 200"
    assert json_get_data.get('status') == "ERROR"
    assert json_get_data.get('message') == 'INTERNAL ERROR'
    assert json_get_data.get('status') != 'OK'

def test_log_read_missing_keys():
    """
    Check for presence of required keys in /log_read response.
    """
    get_response = requests.get(f'{BASE_URL}/log_read')
    json_get_data = get_response.json()

    assert get_response.status_code == 200
    assert 'payload' in json_get_data, "'payload' key missing"
    assert 'data' in json_get_data['payload'], "'data' key missing inside 'payload'"
    assert isinstance(json_get_data['payload']['data'], list), "'data' is not a list"

def test_crud_logs_read_invalid_headers():
    """
    Test /crud_logs endpoint with invalid/missing headers.
    Expecting authentication failure or appropriate error response.
    """
    # Example: Missing JWT token
    invalid_headers = {
        'Jwttoken': 'invalid_or_missing_token'
    }

    get_response = requests.get(f'{BASE_URL}/crud_logs', headers=invalid_headers)
    print('\n')
    print(f"CRUD LOGS READ WITH INVALID HEADER: {get_response.text}")
    
    assert get_response.status_code in [401, 403], "Expected failure due to invalid headers"