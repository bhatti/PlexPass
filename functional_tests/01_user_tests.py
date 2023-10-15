#!/usr/bin/env python
import unittest
import requests
import time
import json

USER_ID = ''
JWT_TOKEN = ''
VERSION = ''
SERVER='https://localhost:8443'

class UsersTest(unittest.TestCase):
    def test_01_signup(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'billy', 'master_password': 'Goose$Billy$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signup', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_02_signin(self):
        global USER_ID
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'billy', 'master_password': 'Goose$Billy$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        USER_ID = json.loads(resp.text)['user_id']
        JWT_TOKEN = resp.headers.get('access_token')

    def test_03_get_user(self):
        global VERSION
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/users/' + USER_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        username = json.loads(resp.text)['username']
        VERSION = json.loads(resp.text)['version']
        self.assertEqual('billy', username)

    def test_04_update_user(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {'user_id':USER_ID, 'version':VERSION, 'username': 'billy',  'name': 'Bill', 'email': 'bill@nowhere'}
        resp = requests.put(SERVER + '/api/v1/users/' + USER_ID, json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_05_get_user_after_update(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/users/' + USER_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        name = json.loads(resp.text)['name']
        email = json.loads(resp.text)['email']
        self.assertEqual('Bill', name)
        self.assertEqual('bill@nowhere', email)


if __name__ == '__main__':
    unittest.main()
