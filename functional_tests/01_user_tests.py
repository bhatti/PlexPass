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
    def test_00_signin_without_signup(self):
        global USER_ID
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 401) # should throw 401 if user doesn't exist

    def test_00_signup_george(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'george@cat.us', 'master_password': 'Goose$geo@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signup', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_01_signup_alice(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'alice@alice.us', 'master_password': 'Goose$ali@dog.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signup', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_02_signup_bob(self):
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signup', json = data, headers = headers, verify = False)
        self.assertTrue(resp.status_code == 200 or resp.status_code == 409)

    def test_03_signin(self):
        global USER_ID
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'bob@cat.us', 'master_password': 'Goose$bob@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        USER_ID = json.loads(resp.text)['user_id']
        JWT_TOKEN = resp.headers.get('access_token')

    def test_04_get_user(self):
        global VERSION
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }
        resp = requests.get(SERVER + '/api/v1/users/' + USER_ID, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        username = json.loads(resp.text)['username']
        VERSION = json.loads(resp.text)['version']
        self.assertEqual('bob@cat.us', username)

    def test_05_update_user(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {'user_id':USER_ID, 'version':VERSION, 'username': 'bob@cat.us',  'name': 'Bill', 'email': 'bill@nowhere'}
        resp = requests.put(SERVER + '/api/v1/users/' + USER_ID, json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_06_get_user_after_update(self):
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

    def test_07_get_user_without_token(self):
        headers = {
            'Content-Type': 'application/json',
        }
        resp = requests.get(SERVER + '/api/v1/users/' + USER_ID, headers = headers, verify = False)
        self.assertEqual(401, resp.status_code)

    def test_08_signin_george(self):
        global USER_ID
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'george@cat.us', 'master_password': 'Goose$geo@cat.us$Goat551'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        USER_ID = json.loads(resp.text)['user_id']
        JWT_TOKEN = resp.headers.get('access_token')

    def test_09_change_password(self):
        headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + JWT_TOKEN,
        }

        data = {'old_password': 'Goose$geo@cat.us$Goat551', 'new_password': 'Goose$geo@cat.us$Goat5511', 'confirm_new_password': 'Goose$geo@cat.us$Goat5511'}
        resp = requests.put(SERVER + '/api/v1/users/' + USER_ID + '/change_password', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)

    def test_10_signin_george_with_new_password(self):
        global USER_ID
        global JWT_TOKEN
        headers = {
            'Content-Type': 'application/json',
        }
        data = {'username': 'george@cat.us', 'master_password': 'Goose$geo@cat.us$Goat5511'}
        resp = requests.post(SERVER + '/api/v1/auth/signin', json = data, headers = headers, verify = False)
        self.assertEqual(200, resp.status_code)
        USER_ID = json.loads(resp.text)['user_id']
        JWT_TOKEN = resp.headers.get('access_token')


if __name__ == '__main__':
    unittest.main()
