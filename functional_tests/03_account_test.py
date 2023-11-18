#!/usr/bin/env python
import unittest
import requests
import time
import json

VAULT_ID = ''
ACCOUNT_ID = ''
JWT_TOKEN = ''
VERSION = ''
SERVER='https://localhost:8443'

class AccountsTest(unittest.TestCase):
    def test_01_signin(self):
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
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

    def test_03_create_accounts(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        data = {'vault_id': VAULT_ID, 'label': 'Costco', 'username': 'alice', 'password': 'Alice#12Wonderland%', 'website_url': 'https://www.costco.com', 'email': 'alice@bitvault.com'}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

        data = {'vault_id': VAULT_ID, 'label': 'Tester', 'username': 'bob', 'password': 'Bob#12Books%', 'website_url': 'https://oreilly.com', 'email': 'bob@bitvault.com'}
        resp = requests.post(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_04_get_accounts(self):
        global ACCOUNT_ID
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts?q=Tester', headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        ACCOUNT_ID = json.loads(resp.text)[0]['account_id']

    def test_05_get_account(self):
        global VERSION
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts/' + ACCOUNT_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        username = json.loads(resp.text)['username']
        VERSION = json.loads(resp.text)['version']
        self.assertEqual('bob', username)

    def test_06_update_account(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {'vault_id': VAULT_ID, 'account_id': ACCOUNT_ID, 'version': VERSION, 'username': 'alice', 'password': 'Alice#12Wonderland%', 'email': 'alice@wonder.land', 'website_url': 'https://disney.com'}
        resp = requests.put(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts/' + ACCOUNT_ID, json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_07_get_account_after_update(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts/' + ACCOUNT_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        version = json.loads(resp.text)['version']
        self.assertTrue(version > VERSION)
        email = json.loads(resp.text)['email']
        self.assertEqual('alice@wonder.land', email)

    def test_08_delete_account(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.delete(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts/' + ACCOUNT_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_08_get_account_without_token(self):
        headers = {
            'Content-Type': 'application/json',
        }
        resp = requests.get(SERVER + '/api/v1/vaults/' + VAULT_ID + '/accounts/' + ACCOUNT_ID, headers = headers, verify = False)
        self.assertEqual(401, resp.status_code)

if __name__ == '__main__':
    unittest.main()
