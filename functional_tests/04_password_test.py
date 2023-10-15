#!/usr/bin/env python
import unittest
import requests
import time
import json

JWT_TOKEN = ''
SERVER='https://localhost:8443'

class AccountsTest(unittest.TestCase):
    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'billy', 'master_password': 'Goose$Billy$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_generate_memorable_password(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/password/memorable', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        password = json.loads(resp.text)['password']
        self.assertTrue(len(password) >= 12)

    def test_03_generate_random_password(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/password/random', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        password = json.loads(resp.text)['password']
        self.assertTrue(len(password) >= 12)

    def test_04_password_compromised(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/password/mypass/compromised', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertEqual(True, json.loads(resp.text)['compromised'])

    def test_04_analyze_password(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/password/mypass/analyze', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertEqual("WEAK", json.loads(resp.text)['strength'])
        self.assertEqual(6, json.loads(resp.text)['length'])



if __name__ == '__main__':
    unittest.main()
