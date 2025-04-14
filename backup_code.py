import requests
import pytest
from models import Payload, LogEntry, Response, EmailValid
import datetime
import json
from pydantic import ValidationError, EmailStr

BASE_URL = "https://beta.tradefinder.in/api_be/admin/log_updates"

# Test for URL /health
def test_health():
    get_response = requests.get(f'{BASE_URL}/health')
    json_get_data = get_response.json()

    assert get_response.status_code == 200
    assert json_get_data['status'] == "OK"
    
# Test for Invalid URL    
def test_invalid_url():
    get_response = requests.get(f'{BASE_URL}/invalid')
    json_get_data = get_response.json()
    
    assert get_response.status_code != 200
    assert json_get_data['status'] == "ERROR"
    assert json_get_data['message'] == 'INTERNAL ERROR'
    assert json_get_data['status'] != 'OK'



# Test for GET:- log_read
def test_read():
    get_response = requests.get(f'{BASE_URL}/log_read')
    json_get_data = get_response.json()

    try:
        response = Response(**json_get_data)
    except ValidationError as e:
        print("Validation error:", e)

    assert get_response.status_code == 200
    assert response.status == 'SUCCESS'
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    json_data_string = json_get_data['payload']['data'][0][1]
    dict_obj = json.loads(json_data_string)

    json_payload = json_get_data['payload']

    try:
        payloadValid = Payload(**json_payload)
    except ValidationError as e:
        print("Validation error:", e)

    try:
        log_entry = LogEntry(**dict_obj)
    except ValidationError as e:
        print("Validation error:", e)
    
    
    
    #------------- Single Value Check -----------------#

    # assert log_entry.Log == "<p>this is test 1 updated one</p>"   # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert log_entry.Log == "<p>this is test 1 updated one</p>"
    # expected_date = datetime.datetime(2024, 12, 14, 17, 31)
    # actual_date = datetime.datetime.fromisoformat(dict_obj['Date'])  
    # assert actual_date == expected_date                             # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert log_entry.Type == "Update"                             # Payload -> data -> ['ts', {Log, Date, Type}]

    # expected_date = datetime.datetime(2024, 12, 14, 17, 31)
    # actual_date = datetime.datetime.fromisoformat(dict_obj['Date'])  
    # assert actual_date == expected_date                              
    # assert dict_obj['Type'] == "Update"                     
             
    # assert json_get_data['payload']['data'][0][1][0] == "<p>this is test 1 updated one</p>"   # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert json_get_data['payload']['data'][0][1][1] == datetime(2024, 12, 14, 17, 31)        # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert json_get_data['payload']['data'][0][1][2] == "Update"                              # Payload -> data -> ['ts', {Log, Date, Type}]

def test_read_missing_keys():
    get_response = requests.get(f'{BASE_URL}/log_read')
    json_get_data = get_response.json()

    assert get_response.status_code == 200
    assert 'payload' in json_get_data, "'payload' key is missing"
    assert 'data' in json_get_data['payload'], "'data' key is missing in payload"
    assert isinstance(json_get_data['payload']['data'], list), "'data' is not a list"


# Test for GET:- crud_logs
def test_read():
    get_response = requests.get(f'{BASE_URL}/crud_logs')
    json_get_data = get_response.json()

    try:
        response = Response(**json_get_data)
    except ValidationError as e:
        print("Validation error:", e)

    assert get_response.status_code == 200
    assert response.status == 'SUCCESS'
    assert isinstance(json_get_data['payload'], dict)
    assert isinstance(json_get_data['payload']['data'], list)

    #--------- Single Value Check from list ------------#
    # data_dict = {
    #     "Log": "<p>this is a log</p>",
    #     "Date": "2024-12-14T17:31",
    #     "Type": "Update"
    # }
    email_string = json_get_data['payload']['data'][0][1]

    json_data_string = json_get_data['payload']['data'][0][2]
    dict_obj = json.loads(json_data_string)

    json_payload = json_get_data['payload']

    try:
        payloadValid = Payload(**json_payload)
    except ValidationError as e:
        print("Validation error:", e)

    try:
        emailValid = EmailValid(email=email_string)
    except ValidationError as e:
        print("Validation error:", e)

    try:
        log_entry = LogEntry(**dict_obj)
    except ValidationError as e:
        print("Validation error:", e)
    
    
    
    #------------- Single Value Check -----------------#

    # assert log_entry.Log == "<p>this is test 1 updated one</p>"   # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert log_entry.Log == "<p>this is test 1 updated one</p>"
    # expected_date = datetime.datetime(2024, 12, 14, 17, 31)
    # actual_date = datetime.datetime.fromisoformat(dict_obj['Date'])  
    # assert actual_date == expected_date                             # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert log_entry.Type == "Update"                             # Payload -> data -> ['ts', {Log, Date, Type}]

    # expected_date = datetime.datetime(2024, 12, 14, 17, 31)
    # actual_date = datetime.datetime.fromisoformat(dict_obj['Date'])  
    # assert actual_date == expected_date                              
    # assert dict_obj['Type'] == "Update"                     
             
    # assert json_get_data['payload']['data'][0][1][0] == "<p>this is test 1 updated one</p>"   # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert json_get_data['payload']['data'][0][1][1] == datetime(2024, 12, 14, 17, 31)        # Payload -> data -> ['ts', {Log, Date, Type}]
    # assert json_get_data['payload']['data'][0][1][2] == "Update"                              # Payload -> data -> ['ts', {Log, Date, Type}]


def test_create():
    input_data = {
        "data" :{   
                "Date": "14-04-2025T12:25",
                # "Date": datetime.now().strftime("%d-%m-%YT%H:%M"),
                "Log": "version 1.24.8",
                "Type": "Release"
        }}
    create_response = requests.post(f'{BASE_URL}/crud_logs', 
                                    json=input_data)
    json_create_data = create_response.json()

    try:
        response = Response(**json_create_data)
    except ValidationError as e:
        print("Response validation error:", e)

    assert create_response.status_code == 200
    assert response.status == 'SUCCESS'


# def test_update():
#     input_data = {
#     "data" :{   
#                 "Date": "09-04-2025T11:30",
#                 "Log": "version 1.24.8",
#                 "Type": "Improvement"
#             },
#     "ts" : "1744178878"
#     }
#     create_response = requests.put(f'{BASE_URL}/crud_logs', 
#                                     json=input_data)
#     json_create_data = create_response.json()

#     try:
#         response = Response(**json_create_data)
#     except ValidationError as e:
#         print("Response validation error:", e)

#     assert create_response.status_code == 200
#     assert response.status == 'SUCCESS'


# def test_delete():
#     delete_data = {
#         "ts" : "1744185023"
#     }
#     delete_response = requests.delete(f'{BASE_URL}/crud_logs',json=delete_data)
#     delete_json_data = delete_response.json()

#     try:
#         response = Response(**delete_json_data)
#     except ValidationError as e:
#         print("Response validation error:", e)

#     assert delete_response.status_code == 200
#     assert response.status == 'SUCCESS'
