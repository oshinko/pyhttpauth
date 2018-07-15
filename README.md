# Python HTTP Authentication

![Python](https://img.shields.io/badge/python-3.6%2C%203.7-blue.svg)

HTTP Authentication.

## Installation

```bash
python -m pip install -U -e git+https://github.com/oshinko/pyvalidation.git#egg=validation
python -m pip install -U -e git+https://github.com/oshinko/pyhttpauth.git#egg=httpauth
```

## Usage

Example with Flask.

```python
import json
import random
import string
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from osnk.httpauth import EmailAuthentication, TokenAuthentication
from osnk.validations import requires

app = Flask(__name__)
secret = b'Your secret words'
email_auth = EmailAuthentication(secret)
email_token = TokenAuthentication(secret, scheme='Email-Token')
device_token = TokenAuthentication(secret, scheme='Device-Token')


@email_auth.authorization
@email_token.authorization
@device_token.authorization
def authorization(header):
    return request.headers.get(header)


@email_auth.authenticate
@email_token.authenticate
@device_token.authenticate
def authenticate(header, scheme):
    return jsonify(error='Unauthorized'), 401, {header: scheme}


@email_token.payload_from_bytes
@device_token.payload_from_bytes
def token_payload_from_bytes(b):
    return json.loads(b.decode())


@email_token.payload_to_bytes
@device_token.payload_to_bytes
def token_payload_to_bytes(payload):
    return json.dumps(payload).encode()


@email_auth.confirm
def email_auth_confirm(credentials, payload):
    return True  # If one-time password, remove the credentials


@email_token.confirm
def email_token_confirm(addrs):
    return True  # Check resource state


@device_token.confirm
def device_token_confirm(payload):
    return True  # Check resource state


def password():
    population = string.ascii_uppercase + string.digits
    return ''.join(random.choices(population, k=12))


def sendmail(credentials):
    print(credentials)  # Publish to the queue


@app.route('/email/auth', methods=['POST'])
def post_email_auth():
    expires = datetime.now() + timedelta(hours=1)
    addrs = request.get_json(force=True)
    credentials = [(addr, password()) for addr in addrs]
    hint = email_auth.hint(credentials, expires, json.dumps(addrs).encode())
    sendmail(credentials)
    return jsonify(hint)


@app.route('/email/token', methods=['GET'])
@requires(email_auth)
def get_email_token():
    expires = datetime.now() + timedelta(hours=1)
    return jsonify(email_token.build(expires, json.loads(email_auth.payload)))


@app.route('/devices/<device>/token', methods=['GET'])
def get_device_token(device):
    expires = datetime.now() + timedelta(hours=1)
    return jsonify(device_token.build(expires, device))


@app.route('/locked/contents', methods=['GET'])
@requires(email_token | device_token)
def get_locked_contents(passed):
    if device_token in passed:
        identity = device_token.payload
    else:
        identity = email_token.payload[0]
    return jsonify({'welcome': identity})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
```

### Token Authentication

```bash
TOKEN=`curl http://localhost:8080/devices/my-curl/token | sed -e 's/^"//' -e 's/"$//'`
curl -H "Authorization: Device-Token $TOKEN" http://localhost:8080/locked/contents
```

### Email Authentication

```bash
HINT=`curl -d '["me@domain"]' http://localhost:8080/email/auth | sed -e 's/^"//' -e 's/"$//'`
ADDR=`echo -n me@domain | base64`
PASS=`echo -n $RECEIVED_PASSWORD | base64`
TOKEN=`curl -H "Authorization: Email $ADDR $PASS $HINT" http://localhost:8080/email/token | sed -e 's/^"//' -e 's/"$//'`
curl -H "Authorization: Email-Token $TOKEN" http://localhost:8080/locked/contents
```
