from flask_sqlalchemy import SQLAlchemy
import unittest
import json
from passlib.hash import bcrypt

from app import app, db
from app.models import User
from base_testcase import BaseTest


class UserResourceTest(BaseTest):
    def setUp(self):
        super(UserResourceTest, self).setUp()

    def tearDown(self):
        super(UserResourceTest, self).tearDown()

    #user login tests
    def test_login_returns_ok_status_code(self):
        user = {
            "username": self.saved_user.username,
            "password": "lion"
        }
        response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 200)

    def test_login_success_response_has_token(self):
        user = {
            "username": self.saved_user.username,
            "password": "lion"
        }
        response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 200)
        self.assertTrue(b'access_token' in response.data)

    def test_wrong_login_credentials_returns_correct_message(self):
        user = {
            "username": "john",
            "password": "dorian"
        }
        response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Invalid credentials' in response.data)

    def test_login_with_empty_submit_returns_correct_message(self):
        user = {
            "username": "",
            "password": ""
        }
        response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(b'Invalid credentials' in response.data)
    
    #user register tests
    def test_register_returns_ok_status_code(self):
        user = self.temp_user
        response = self.client.post(
            '/api/v1/auth/register', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 201)

    def test_succesful_register_contains_success_message(self):
        user = self.temp_user
        response = self.client.post(
            '/api/v1/auth/register', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(b'user successfully registered!'
                        in response.data)

    def test_register_missing_username_message(self):
        user = self.temp_user
        user['username'] = ''
        response = self.client.post(
            '/api/v1/auth/register', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 400)
        self.assertTrue(b'username is required' in response.data)

    def test_register_missing_email_message(self):
        user = self.temp_user
        user['email'] = ''
        response = self.client.post(
            '/api/v1/auth/register', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 400)
        self.assertTrue(b'email is required' in response.data)


    def test_register_password_doesnt_match_confirm_message(self):
        user = self.temp_user
        user['confirm_password'] = 'wrong'
        response = self.client.post(
            '/api/v1/auth/register', data=json.dumps(user),
            headers=self.headers)
        self.assertTrue(response.status_code == 400)
        self.assertTrue(b'password should match '
                        b'confirm password' in response.data)
    