from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app


def generate_token(id, expires=3600):
    s = Serializer(current_app.config['SECRET_KEY'], expires_in=expires)
    return s.dumps({'id': id})


def deserialize_token(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except:
        return None
    return data.get('id')
