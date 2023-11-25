#!/usr/bin/env python
import unittest
import requests
import time
import json

JWT_TOKEN = ''
SERVER='https://localhost:8443'
OTP_SECRET = 'O4YLRYMTIYDAJH2JUHGNQKM4RMVH3T63LZ3VYQQ6O6R3TER2MRFA'
OTP_CODE = ''

class CategoryTest(unittest.TestCase):
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

    def test_02_create_category(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.post(SERVER + '/api/v1/categories', json = {'name': 'Crypto & Bets'}, headers = headers, verify = False)
        print(resp.text)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)
        resp = requests.post(SERVER + '/api/v1/categories', json = {'name': 'Gaming'}, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_03_get_categories(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/categories', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_05_delete_category(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.delete(SERVER + '/api/v1/categories/Crypto & Bets', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

if __name__ == '__main__':
    unittest.main()
