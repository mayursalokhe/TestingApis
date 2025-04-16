from pydantic import BaseModel, EmailStr
from typing import List

# {"name":"harshada","email":"hr@gmail.com","contact":"8433544979","message":"this is testing contact message"}
class LogEntry(BaseModel):
    ts: str
    name: str
    email: EmailStr
    contact: str
    message: str

# {'payload': {'data': [['1744796400', 'hr@gmail.com', 'harshada', '8433544979', 'this is testing contact message'], ['1727689882', 'nayan@gmail.com', 'nayan', '7894561230', 'This is a testing message']]}
class Payload(BaseModel):
    data: List[List[str]]

class Response(BaseModel):
    status: str