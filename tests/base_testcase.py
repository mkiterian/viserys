import unittest
from passlib.hash import bcrypt

from app import app, db
from app.models import User, Bucketlist


class BaseTest(unittest.TestCase):
    def setUp(self):
        #setup test environment configuration
        app.config.from_object('config.TestingConfig')
        self.client = app.test_client()
        db.drop_all()
        db.create_all()

        self.headers = {"Content-Type": "application/json"}
        #define a user to be used for registration tests
        self.temp_user = {
            "username": "Sansa",
            "email": "sansa@gmail.com",
            "password": "wicked",
            "confirm_password": "wicked"
        }

        #define an existing user
        self.saved_user = User("tyrion", "tyrion@gmail.com",
                               bcrypt.hash("lion", rounds=12))
        self.saved_user_2 = User("theon", "theon@gmail.com",
                               bcrypt.hash("qwerty", rounds=12))
        db.session.add(self.saved_user)
        db.session.add(self.saved_user_2)
        db.session.commit()        

    def tearDown(self):
        db.session.remove
        db.drop_all()
