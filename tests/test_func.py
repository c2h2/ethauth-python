import sys, os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../')

import ethauth


token = "eyJuYW1lIjoiYWxpY2UiLCJjcmVhdGVkIjoxNDU5MjEwMDg1MDA4fQ.eyJ2IjoyNywiciI6IjVhZTQzODM2MDY1MGI3OWY3Yzg1OTFiOGE5MjY0NTQxZjUxMzk4MDBkODNlNDU5ZTc1NjQ1ODgwY2QwYTgwY2IiLCJzIjoiNzg2ZWMwNDcwMjVjNDk3Yjk3YzUyZWZiMDAyOThmZmM1OGQ5ZWE3MmJjMTNlNzQwNDA2NzBmNGY1OWFjNTVmNSJ9"


alice = {'id': "0xa819f0ff06a47610f78e7ccaed67cc51314dbe19",
         'password': "hello alice"}
bob = {'id': "0x27db8a572e88a99cab98bddf7f55273556337da0",
       'password': "hello bob"}

def test_round_trip():
    sk = ethauth.sha256(bob['password'])
    token = ethauth.sign(sk, {'name': 'bob'})
    assert token
    assert len(token.split('.')) == 2

    result = ethauth.validate(token)
    assert result['id'] == bob['id']
    assert result['payload']['name'] == 'bob'
    assert result['payload']['created']

def test_validate_token():
    result = ethauth.validate(token)
    assert result['id'] == alice['id']
    assert result['payload']['name'] == 'alice'
    assert result['payload']['created']

def test_fail_bad_token():
    result = ethauth.validate('badtoken')
    assert not result
    result2 = ethauth.validate('bad.token')
    assert not result2
