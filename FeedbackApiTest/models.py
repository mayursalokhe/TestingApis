from pydantic import BaseModel, EmailStr
from typing import List
from enum import Enum
import re

class Categories(str, Enum):
    market_pulse = 'Market Pulse'
    insider_strategy = 'Insider Strategy'
    sector_scope = 'Sector Scope'
    swing_spectrum = 'Swing Spectrum'
    option_clock = 'Option Clock'
    option_apex = 'Option Apex'
    trding_journal = 'Trading Journal'
    other = 'Other'

# 'data': [['1744949857', 'ex@gmail.com', 'mayur', '1234567890', 'Market Pulse', '', 'good'],['1744949333', 'h@gmail.com', 'harshada', '917854623564', 'Other', '', 'good']
class LogEntry(BaseModel):
    ts: str
    email: EmailStr
    name: str
    whatsapp: str
    category: Categories
    image: str
    feedback: str

# .{'payload': {'data': [['1744949857', 'ex@gmail.com', 'mayur', '1234567890', 'Market Pulse', '', 'good'], ['1744949333', 'h@gmail.com', 'harshada', '917854623564', 'Other', '', 'good'], ['1740422237', 'dknaix@gmail.com', "<script>alert('XSS Attack!');</script>", '9876543100', 'Other', '', "<script>alert('XSS Attack!');</script>"], ['1738238501', 'dknaix@gmail.com', 'asdas  sdfg sdfh shg', '9876543210', 'Insider Strategy', '', 'asd gs d sdfh ']]}, 'status': 'SUCCESS'}
class Payload(BaseModel):
    data: List[List[str]]
 
# response status 
class Response(BaseModel):
    status: str