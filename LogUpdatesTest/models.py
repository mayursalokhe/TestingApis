from pydantic import BaseModel, EmailStr
from typing import List
from datetime import datetime
from enum import Enum

class LogType(str, Enum):
    RELEASE = 'Release'
    UPDATED = 'Updated'
    IMPROVEMENT = 'Improvement'

#  ['1734178729', '{"Log": "<p>dfgdsfsdfgsd</p>", "Date": "2024-12-04T17:48", "Type": "Update"}']
class LogEntry(BaseModel):
    Log: str
    Date: datetime
    # Type: LogType
    Type: str

# {'payload': {'data': [ ['1734178729', '{"Log": "<p>dfgdsfsdfgsd</p>", "Date": "2024-12-04T17:48", "Type": "Update"}'], ['1734178736', '{"Log": "<p>dfgghfhjjuuy</p>", "Date": "2024-12-27T17:48", "Type": "Update"}'], ['1744177050', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744177299', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744177329', '{"Log": "version 1.24.8", "Date": "14-12-2024T15:29", "Type": "updated"}'], ['1744180886', '{"Log": "version 1.24.8", "Date": "09-04-2025T11:30", "Type": "updated"}'], ['1744632825', '{"Log": "version 1.24.9 - Updated", "Date": "15-04-2025T10:00", "Type": "Improvement"}'], ['1744705177', '{"Log": "version 1.24.8", "Date": "14-04-2025T12:25", "Type": "Release"}']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]

# response staus
class Response(BaseModel):
    status: str

class EmailValid(BaseModel):
    email: EmailStr

