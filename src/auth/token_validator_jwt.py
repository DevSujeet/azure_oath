import jwt

def inspect_token(token: str):
    decoded = jwt.decode(token, options={"verify_signature": False})
    print(decoded)
    return decoded
