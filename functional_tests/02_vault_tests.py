#!/usr/bin/env python
import unittest
import requests
import time
import json

VAULT_ID = ''
JWT_TOKEN = ''
VERSION = ''
SERVER='https://localhost:8443'

class VaultsTest(unittest.TestCase):
    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        JWT_TOKEN = resp.headers.get('access_token')

    def test_02_create_vault(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {'title': 'Bobcat'}
        resp = requests.post(SERVER + '/api/v1/vaults', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_03_get_vaults(self):
        global VAULT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        VAULT_ID = [vault for vault in json.loads(resp.text) if vault['title'] == 'Bobcat'][0]['vault_id']

    def test_04_get_vault(self):
        global VERSION
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID, headers = headers, verify = False)
        title = json.loads(resp.text)['title']
        VERSION = int(json.loads(resp.text)['version'])
        self.assertEqual(200, resp.status_code)

    def test_05_update_vault(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {'vault_id':VAULT_ID, 'version':VERSION, 'title': 'Bobcat'}
        resp = requests.put(SERVER + '/api/v1/vaults/' + VAULT_ID, json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_06_get_vault_after_update(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        version = int(json.loads(resp.text)['version'])
        self.assertTrue(version > VERSION)

    def test_07_get_vault_without_token(self):
        headers = {
            'Content-Type': 'application/json',
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID, headers = headers, verify = False)
        self.assertEqual(401, resp.status_code)

    def test_08_analyze_vault_passwords(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID + '/analyze_passwords', json = data, headers = headers, verify = False)
        self.assertEqual(202, resp.status_code)

if __name__ == '__main__':
    unittest.main()
