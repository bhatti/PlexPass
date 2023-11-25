#!/usr/bin/env python
import unittest
import requests
import time
import json

VAULT_ID = ''
JWT_TOKEN = ''
SERVER='https://localhost:8443'
VAULT_LEN = 0
OTP_SECRET = 'O4YLRYMTIYDAJH2JUHGNQKM4RMVH3T63LZ3VYQQ6O6R3TER2MRFA'
OTP_CODE = ''

class ShareVaultTest(unittest.TestCase):
    def test_00_otp(self):
        global OTP_CODE
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'otp_secret': OTP_SECRET}
        resp = requests.post(SERVER + '/api/v1/otp/generate', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        OTP_CODE = json.loads(resp.text)['otp_code']

    def test_01_signin_as_bob(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551', 'otp_code': OTP_CODE}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_get_vaults(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        VAULT_ID = json.loads(resp.text)[0]['vault_id']

    def test_03_get_vault(self):
        global VAULT_LEN
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID, headers = headers, verify = False)
        title = json.loads(resp.text)['title']
        self.assertEqual(200, resp.status_code)
        entries = json.loads(resp.text)['entries']
        VAULT_LEN = len(entries)

    def test_04_share_vault_with_alice(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {'target_username': 'alice@alice.us'}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID + '/share', headers = headers, json = data, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_05_signin_as_alice(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'alice@alice.us', 'master_password': 'Goose$ali@dog.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_06_get_vaults_as_alice(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_03_get_vault_as_alice(self):
        global VERSION
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID, headers = headers, verify = False)
        title = json.loads(resp.text)['title']
        VERSION = int(json.loads(resp.text)['version'])
        self.assertEqual(200, resp.status_code)
        entries = json.loads(resp.text)['entries']
        self.assertEqual(VAULT_LEN, len(entries))

if __name__ == '__main__':
    unittest.main()
