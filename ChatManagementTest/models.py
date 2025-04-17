from pydantic import BaseModel, EmailStr
from typing import List

# {'data': [['1744868900', '', 'kfcalulb'], ['1738305181', '', '<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>']]}
class LogPublicEntry(BaseModel):
    ts: str
    url: str
    text: str

# {'data': [['1744868900', 'harshada@gmail.com', '', 'kfcalulb'], ['1738305181', 'dknaix@gmail.com', '', '<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>']]}
class LogEntry(BaseModel):
    ts: str
    email: EmailStr
    url: str
    text: str

#  {'payload': {'data': [['1744868900', '', 'kfcalulb'], ['1738305181', '', '<p>Dead Users,</p><p>Please note that Tradefinder data will not be updated tomorrow, February 1st (Saturday). Thank you.</p>']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]
 
class Response(BaseModel):
    status: str