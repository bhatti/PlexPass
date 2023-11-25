#!/usr/bin/env python
import unittest
import requests
import time
import json

JWT_TOKEN = ''
SERVER='https://localhost:8443'
PK = ''
SK = ''
OTP_SECRET = 'O4YLRYMTIYDAJH2JUHGNQKM4RMVH3T63LZ3VYQQ6O6R3TER2MRFA'
OTP_CODE = ''

class EncryptionTest(unittest.TestCase):
    def test_00_otp(self):
        global OTP_CODE
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'otp_secret': OTP_SECRET}
        resp = requests.post(SERVER + '/api/v1/otp/generate', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        OTP_CODE = json.loads(resp.text)['otp_code']

    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551', 'otp_code': OTP_CODE}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_asymmetric_key_gen(self):
        global PK
        global SK
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {}
        resp = requests.post(SERVER + '/api/v1/encryption/generate_keys', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        PK = json.loads(resp.text)['public_key']
        SK = json.loads(resp.text)['secret_key']
        self.assertTrue(len(PK) >= 10)
        self.assertTrue(len(SK) >= 10)

    def test_03_asymmetric_encryption(self):
        global PK
        global SK
            #'Content-Type': 'application/octet-stream',
        headers = {
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = 'hello world'
        resp = requests.post(SERVER + '/api/v1/encryption/asymmetric_encrypt/' + PK, data = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        encrypted = resp.text
        resp = requests.post(SERVER + '/api/v1/encryption/asymmetric_decrypt/' + SK, data = encrypted, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(data, resp.text)

    def test_04_symmetric_encryption(self):
        global PK
        global SK
            #'Content-Type': 'application/octet-stream',
        headers = {
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        password = 'password'
        data = 'hello world'
        resp = requests.post(SERVER + '/api/v1/encryption/symmetric_encrypt/' + password, data = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        encrypted = resp.text
        resp = requests.post(SERVER + '/api/v1/encryption/symmetric_decrypt/' + password, data = encrypted, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(data, resp.text)

if __name__ == '__main__':
    unittest.main()
