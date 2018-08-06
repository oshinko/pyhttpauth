import base64
import datetime
import functools
import hmac
import hashlib
import osnk.validations
import re


def b64decode(s):
    missing_padding = len(s) % 4
    if missing_padding != 0:
        s += '=' * (4 - missing_padding)
    return base64.b64decode(s)


class HTTPAuthentication(osnk.validations.Validation):
    def __init__(self, scheme,
                 authorization_header='Authorization',
                 authenticate_header='WWW-Authenticate'):
        self.scheme = scheme
        self.authorization_header = authorization_header
        self.authenticate_header = authenticate_header

    def parse_authorization(self, authorization):
        raise NotImplementedError()

    def authorization(self, fn):
        """header の内容 (scheme を含む全ての文字列) を返却.
        """
        @functools.wraps(fn)
        def wrapper():
            authorization = fn(self.authorization_header)
            if authorization:
                if self.scheme:
                    p = f'{self.scheme} +([^,]+)'
                    m = re.search(p, authorization)
                    if m:
                        return self.parse_authorization(m.group(1))
                else:
                    return self.parse_authorization(authorization)
        self.get_authorization = wrapper
        return fn

    def authenticate(self, fn):
        @functools.wraps(fn)
        def wrapper():
            return fn(self.authenticate_header, self.scheme)
        self.get_authenticate = wrapper
        return fn


def splitvarlen(b, n):
    current = 0
    for _ in range(n):
        count = b[current]
        current += 1
        yield b[current:current + count]
        current += count
    yield b[current:]


class TokenAuthentication(HTTPAuthentication):
    def __init__(self, secret, scheme='Bearer', *args, **kwargs):
        if not isinstance(secret, (bytes, bytearray)):
            raise TypeError(("Secret was expected bytes or bytearray, "
                             "but got 'str'"))
        self.secret = secret
        super().__init__(scheme, *args, **kwargs)

    def payload_from_bytes(self, fn):
        self._payload_from_bytes = fn
        return fn

    def payload_to_bytes(self, fn):
        self._payload_to_bytes = fn
        return fn

    def build(self, expires, payload):
        ebin = int(expires.timestamp()).to_bytes(8, 'big').lstrip(b'\0')
        elen = len(ebin).to_bytes(1, 'big')
        pbin = self._payload_to_bytes(payload)
        plen = len(pbin).to_bytes(1, 'big')
        sign = hmac.new(self.secret, ebin + pbin, hashlib.sha256)
        data = elen + ebin + plen + pbin + sign.digest()
        return base64.b64encode(data).decode().rstrip('=')

    def parse_authorization(self, token):
        try:
            b = b64decode(token)
        except Exception:
            return
        ebin, pbin, signature = splitvarlen(b, 2)
        expires = datetime.datetime.fromtimestamp(int.from_bytes(ebin, 'big'))
        payload = self._payload_from_bytes(pbin)
        return (ebin, expires), (pbin, payload), signature

    def _now(self):
        return datetime.datetime.now()

    def now(self, fn):
        self._now = fn
        return fn

    def _confirm(self, payload):
        return True

    def confirm(self, fn):
        self._confirm = fn
        return fn

    def validate(self, *args, **kwargs):
        authorization = self.get_authorization()
        if not authorization:
            return self.get_authenticate()
        (ebin, expires), (pbin, payload), signature = authorization
        if expires < self._now():
            return self.get_authenticate()
        sig = hmac.new(self.secret, ebin + pbin, hashlib.sha256)
        if not hmac.compare_digest(signature, sig.digest()) or \
           not self._confirm(payload):
            return self.get_authenticate()

    @property
    def payload(self):
        _, (_, payload), _ = self.get_authorization()
        return payload


class EmailAuthentication(HTTPAuthentication):
    """Email Authentication.

    >>> secret = '秘密のテキスト'.encode()
    >>> auth = EmailAuthentication(secret)
    >>> credentials = [('me@domain', 'password'),
    ...                ('me@second.domain', 'password')]
    >>> expires = datetime.datetime(2018, 1, 1)
    >>> hint = auth.hint(credentials, expires)
    >>> response = ' '.join(base64.b64encode(y.encode()).decode().rstrip('=')
    ...                     for x in credentials for y in x)
    >>> headers = {'Authorization': f'Email {response} {hint}'}
    >>> print(headers)
    {'Authorization': 'Email bWVAZG9tYWlu cGFzc3dvcmQ \
bWVAc2Vjb25kLmRvbWFpbg cGFzc3dvcmQ \
BFpI+3AA48GoHltploblnM/ogRiwnOV7UmEMqFB7ZPTVkDh20qw'}
    >>> @auth.authorization
    ... def authorization(header):
    ...     return headers.get(header, None)
    >>> @auth.authenticate
    ... def authenticate(header, scheme):
    ...     return (header, scheme)
    >>> @auth.now
    ... def now():
    ...     return expires - datetime.timedelta(microseconds=1)
    >>> from osnk.validations import requires
    >>> @requires(auth)
    ... def index(passed):
    ...     assert auth in passed, 'A bug in the validation module'
    ...     return 'Hello!'
    >>> index()
    'Hello!'
    """
    def __init__(self, secret, scheme='Email', *args, **kwargs):
        if not isinstance(secret, (bytes, bytearray)):
            raise TypeError(("Secret was expected bytes or bytearray, "
                             "but got 'str'"))
        self.secret = secret
        super().__init__(scheme, *args, **kwargs)

    def _sign(self, credentials, expires, payload):
        if isinstance(expires, (bytes, bytearray)):
            ebin = expires
        elif isinstance(expires, datetime.datetime):
            ebin = int(expires.timestamp()).to_bytes(8, 'big').lstrip(b'\0')
        elif isinstance(expires, int):
            ebin = int(eint).to_bytes(8, 'big').lstrip(b'\0')
        else:
            raise TypeError(("Expires was expected bytes or datetime"))
        mstr = ''
        for address, password in sorted(credentials):
            mstr += f'{address}{password}'
        mbin = mstr.encode() + ebin + payload
        return mbin, ebin, hmac.new(self.secret, mbin, hashlib.sha256)

    def hint(self, credentials, expires, payload=b''):
        _, ebin, sign = self._sign(credentials, expires, payload)
        elen = len(ebin).to_bytes(1, 'big')
        plen = len(payload).to_bytes(1, 'big')
        hbin = elen + ebin + plen + payload + sign.digest()
        r = base64.b64encode(hbin).decode()
        return r.rstrip('=')

    def parse_authorization(self, authorization):
        args = [x for x in authorization.split(' ') if x]
        s = len(args)
        if s >= 3 and s % 2 != 0:
            try:
                credentials = tuple((b64decode(args[i]).decode(),
                                     b64decode(args[i + 1]).decode())
                                    for i in range(0, len(args) - 1, 2))
            except Exception:
                return
            hint = args[-1]
            b = b64decode(hint)
            ebin, payload, signature = splitvarlen(b, 2)
            expires = datetime.datetime.fromtimestamp(
                int.from_bytes(ebin, 'big'))
            return credentials, (expires, payload, signature)

    def _now(self):
        return datetime.datetime.now()

    def now(self, fn):
        self._now = fn
        return fn

    def _verify(self, credentials, expires, payload, signature):
        _, _, sig = self._sign(credentials, expires, payload)
        return hmac.compare_digest(signature, sig.digest())

    def _confirm(self, credentials, payload):
        return True

    def confirm(self, fn):
        self._confirm = fn
        return fn

    def validate(self, *args, **kwargs):
        authorization = self.get_authorization()
        if not authorization:
            return self.get_authenticate()
        credentials, (expires, payload, signature) = authorization
        if expires <= self._now():
            return self.get_authenticate()
        if not self._verify(credentials, expires, payload, signature) or \
           not self._confirm(credentials, payload):
            return self.get_authenticate()

    @property
    def payload(self):
        _, (_, payload, _) = self.get_authorization()
        return payload
