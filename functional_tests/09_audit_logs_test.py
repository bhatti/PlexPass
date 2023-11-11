#!/usr/bin/env python
import unittest
import requests
import time
import json

VAULT_ID = ''
JWT_TOKEN = ''
SERVER='https://localhost:8443'
VAULT_LEN = 0 

class AuditLogsTest(unittest.TestCase):
    def test_01_signin_as_bob(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_get_logs(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/audit_logs', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

if __name__ == '__main__':
    unittest.main()
