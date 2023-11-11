#!/usr/bin/env python
import unittest
import requests
import time
import json

JWT_TOKEN = ''
SERVER='https://localhost:8443'

class PasswordTest(unittest.TestCase):
    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_generate_memorable_password(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {}
        resp = requests.post(SERVER + '/api/v1/password/memorable', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        password = json.loads(resp.text)['password']
        self.assertTrue(len(password) >= 12)

    def test_03_generate_random_password(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {}
        resp = requests.post(SERVER + '/api/v1/password/random', json = data, headers = headers, verify = False)
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

    def test_05_email_compromised(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/emails/mypass/compromised', headers = headers, verify = False)
        self.assertEqual(400, resp.status_code) # without hibp key - should fail

    def test_06_check_password_strength(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/password/mypass/strength', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        self.assertEqual("WEAK", json.loads(resp.text)['strength'])
        self.assertEqual(6, json.loads(resp.text)['length'])

    def test_07_get_check_password_strength_without_token(self):
        headers = {
            'Content-Type': 'application/json',
        }
        resp = requests.get(SERVER + '/api/v1/password/mypass/strength', headers = headers, verify = False)
        self.assertEqual(401, resp.status_code)

    def test_08_analyze_all_passwords(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {}
        resp = requests.post(SERVER + '/api/v1/password/analyze_all_passwords', json = data, headers = headers, verify = False)
        self.assertEqual(202, resp.status_code)


if __name__ == '__main__':
    unittest.main()
