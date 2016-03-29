
import base64
import json
import hashlib
import binascii
from bitcoin import ecdsa_raw_sign,ecdsa_raw_recover,encode_pubkey,encode,decode
import sha3 as _sha3
sha3_256 = lambda x: _sha3.sha3_256(x).digest()


def sign(sk, data):
    """
     Sign some data with a secret key.
    """
    payload = data or {}
    token = []
    payload['created'] = _utc_timestamp()
    encodedPayload = encode64(json.dumps(payload))
    token.append(encodedPayload)

    hash = sha256(encodedPayload)
    v, r, s = ecdsa_raw_sign(hash, sk)
    sigObj = {'v': v,
              'r': to_hex(r),
              's': to_hex(s)
              }
    encodedSignature = encode64(json.dumps(sigObj))
    token.append(encodedSignature)
    return '.'.join(token)


def validate(token):
    """
    Validate a given token. Returns an object if valid or None
    """
    try:
        parts = token.split('.')
        sig = json.loads(decode64(parts[1]))
        vrs = (sig['v'], from_hex(sig['r']), from_hex(sig['s']))
        q = ecdsa_raw_recover(sha256(parts[0]), vrs)
        return {
            'id': pubToEtherAddress(q),
            'payload': json.loads(decode64(parts[0]))
        }
    except Exception as e:
        return None


def sha256(m):
    return hashlib.sha256(m).hexdigest()


def encode64(s):
    return base64.urlsafe_b64encode(s).replace('=', '')


def decode64(s):
    return base64.urlsafe_b64decode(_padString(s))


def _padString(s):
    diff = len(s) % 4
    if not diff:
        return s
    padLength = 4 - diff
    for i in range(0, padLength):
        s += '='
    return s


def pubToEtherAddress(q):
    pk = encode_pubkey(q, 'hex')
    if len(pk) > 32:
        pk = binascii.unhexlify(pk)
    return '0x{}'.format(binascii.hexlify(sha3_256(pk[1:])[12:]))


def _utc_timestamp():
    from calendar import timegm
    from datetime import datetime
    return timegm(datetime.utcnow().utctimetuple())


def to_hex(value):
    return binascii.hexlify(encode(value, 256))


def from_hex(value):
    return decode(binascii.unhexlify(value), 256)
