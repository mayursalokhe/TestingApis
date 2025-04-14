from pydantic import BaseModel, EmailStr
from typing import List
from datetime import datetime
from enum import Enum

class LogType(str, Enum):
    RELEASE = 'Release'
    UPDATED = 'Updated'
    IMPROVEMENT = 'Improvement'


class LogEntry(BaseModel):
    Log: str
    Date: datetime
    # Type: LogType
    Type: str

class Payload(BaseModel):
    data: List[List[str]]

class CrudGet(BaseModel):
    pass

class Response(BaseModel):
    status: str

class EmailValid(BaseModel):
    email: EmailStr

# Example:
# json_data = {
#     "payload": {
#         "data": [
#             [
#                 "1734177675",
#                 "{\"Log\": \"<p>this is test 1 updated one</p>\", \"Date\": \"2024-12-14T17:31\", \"Type\": \"Update\"}"
#             ],
#             [
#                 "1734177699",
#                 "{\"Log\": \"<p>this is test 2</p>\", \"Date\": \"2024-12-14T17:31\", \"Type\": \"Release\"}"
#             ],
#             [
#                 "1734177711",
#                 "{\"Log\": \"<p>this is test 3</p>\", \"Date\": \"2024-12-14T17:31\", \"Type\": \"Improvement\"}"
#             ],
#             [
#                 "1734178729",
#                 "{\"Log\": \"<p>dfgdsfsdfgsd</p>\", \"Date\": \"2024-12-04T17:48\", \"Type\": \"Update\"}"
#             ],
#             [
#                 "1734178736",
#                 "{\"Log\": \"<p>dfgghfhjjuuy</p>\", \"Date\": \"2024-12-27T17:48\", \"Type\": \"Update\"}"
#             ]
#         ]
#     },
#     "status": "SUCCESS"
# }

# response = Response.model_validate(json_data)
# print(response)
