#!/usr/bin/env python
import unittest
import requests
import time
import json

USER_ID = ''
JWT_TOKEN = ''
SERVER='https://localhost:8443'

class UsersTest(unittest.TestCase):
    def test_08_reset_mfa(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'otp_secret': 'O4YLRYMTIYDAJH2JUHGNQKM4RMVH3T63LZ3VYQQ6O6R3TER2MRFA'}
        resp = requests.post(SERVER + '/api/v1/otp/generate', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        otp = json.loads(resp.text)['otp_code']

        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551', 'otp_code': otp}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {'recovery_code': 'MKivPbLKJRqX'}
        resp = requests.post(SERVER + '/api/v1/auth/reset_mfa', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

if __name__ == '__main__':
    unittest.main()
