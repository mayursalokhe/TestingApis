import pyotp

SECRET_KEY = pyotp.random_base32()

def get_jwttoken():
    jwttoken = ''    
    return jwttoken

def get_accesstoken():
    accesstoken_obj = pyotp.TOTP(SECRET_KEY, interval=30)
    return accesstoken_obj.now()

 