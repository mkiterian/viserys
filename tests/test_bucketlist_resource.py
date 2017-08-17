import unittest
import json
from passlib.hash import bcrypt
from flask_sqlalchemy import SQLAlchemy

from app import app, db
from app.models import User, Bucketlist
from base_testcase import BaseTest


class BucketlistResourceTest(BaseTest):
    def setUp(self):
        super(BucketlistResourceTest, self).setUp()
        self.user = {
            "username": self.saved_user.username,
            "password": "lion"
        }

        self.other_user = {
            "username": self.saved_user_2.username,
            "password": "qwerty"
        }

        # create a bucketlist for tyrion
        current_user = User.query.filter_by(
            username=self.saved_user.username).first()
        self.example_bucketlist_one = Bucketlist(
            "bucketlist_one",
            "this is an example bucketlist",
            current_user.id)
        db.session.add(self.example_bucketlist_one)
        db.session.commit()

        # create a second bucketlist for tyrion
        self.example_bucketlist_two = Bucketlist(
            "bucketlist_two",
            "this is an another bucketlist",
            current_user.id)
        db.session.add(self.example_bucketlist_two)
        db.session.commit()

        self.bucketlist_one_id = Bucketlist.query.filter_by(
            name="bucketlist_one").first().id

        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

    def tearDown(self):
        super(BucketlistResourceTest, self).tearDown()

    # view bucketlists tests
    def test_view_bucketlists_status_code_is_ok(self):
        response = self.client.get(
            '/api/v1/bucketlists', data=json.dumps(self.user),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_if_bucketlist_name_is_returned(self):
        response = self.client.get(
            '/api/v1/bucketlists', data=json.dumps(self.user),
            headers=self.headers)
        self.assertTrue(b'bucketlist_one' in response.data)

    def test_all_bucketlists_are_returned(self):
        response = self.client.get(
            '/api/v1/bucketlists',
            headers=self.headers)
        self.assertTrue(b'bucketlist_one' in response.data
                        and b'bucketlist_two' in response.data)

    def test_cant_view_bucketlists_without_token(self):
        no_token = self.headers
        no_token['Authorization'] = ""
        response = self.client.get(
            '/api/v1/bucketlists', data=json.dumps(self.user),
            headers=no_token)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Authorization Required' in response.data)

    def test_user_cant_view_second_bucketlist_when_limit_is_one(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(limit='1'),
            headers=self.headers)
        self.assertTrue(response.data.count(b'id'), 1)
        self.assertFalse(b'bucketlist_two' in response.data)

    def test_user_can_view_items_when_page_is_specified(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(page='1'),
            headers=self.headers)
        self.assertTrue(response.data.count(b'id'), 2)
        self.assertTrue(b'bucketlist_one' in response.data)

    def test_user_can_search_via_api(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(q='one'),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'bucketlist_one' in response.data)

    def test_message_when_q_is_specified_with_nonexistent_page(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(q='one', page=333),
            headers=self.headers)
        self.assertEqual(response.status_code, 404)
        self.assertTrue(b'Page does not exist' in response.data)

    def test_page_specified_does_not_exist_message(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(page='2000'),
            headers=self.headers)
        self.assertTrue(response.status_code == 404)
        self.assertTrue(b'Page does not exist' in response.data)

    def test_next_page_is_page_2_when_page_is_set_to_1(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(page='1'),
            headers=self.headers)
        self.assertTrue(b'"next": "/api/v1/bucketlists?'
                        b'page=2&limit=10"' in response.data)

    def test_bucketlist_returned_when_q_is_specified(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(q='two'),
            headers=self.headers)
        self.assertTrue(response.status_code == 200)
        self.assertTrue(b'bucketlist_two' in response.data)

    def test_message_when_name_in_q_does_not_exist(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists',
            query_string=dict(q='millions'),
            headers=self.headers)
        self.assertTrue(response.status_code == 404)
        self.assertTrue(b'Bucketlist does not exist' in response.data)

    # view specific bucketlist
    def test_successful_status_code_when_bucket_id_is_specified(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}'.format(self.bucketlist_one_id),
            data=json.dumps(self.user),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)

    def test_bucketlist_name_is_returned_given_id(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}'.format(self.bucketlist_one_id),
            data=json.dumps(self.user),
            headers=self.headers)

        self.assertTrue(b'bucketlist_one' in response.data)

    def test_only_one_bucketlist_is_returned_given_id(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}'.format(self.bucketlist_one_id),
            data=json.dumps(self.user),
            headers=self.headers)

        self.assertEqual(response.data.count(b'id'), 1)

    def test_response_message_for_non_existent_id(self):
        response = self.client.get(
            '/api/v1/bucketlists/2000',
            data=json.dumps(self.user),
            headers=self.headers)
        self.assertTrue(b'requested id does not exist' in response.data)

    # create bucketlist tests
    def test_bucketlist_created_successfully_message(self):
        new_bucketlist = {
            "name": "new bucketlist",
            "description": "this is a test bucketlist"
        }
        response = self.client.post(
            '/api/v1/bucketlists',
            data=json.dumps(new_bucketlist),
            headers=self.headers)
        self.assertTrue(response.status_code, 201)
        self.assertTrue(
            b'bucketlist created successfully' in response.data)

    def test_create_bucketlist_request_missing_field_message(self):
        new_bucketlist = {
            "name": "new bucketlist"
        }
        response = self.client.post(
            '/api/v1/bucketlists',
            data=json.dumps(new_bucketlist),
            headers=self.headers)
        self.assertTrue(b'Missing required parameter' in response.data)

    def test_create_bucketlist_request_with_empty_strings(self):
        new_bucketlist = {
            "name": "",
            "description": "this has no name"
        }
        response = self.client.post(
            '/api/v1/bucketlists',
            data=json.dumps(new_bucketlist),
            headers=self.headers)
        self.assertTrue(b'empty strings not allowed' in response.data)

    def test_cant_create_bucketlist_without_authentication(self):
        new_bucketlist = {
            "name": "Not allowed",
            "description": "I have not been authenticated!"
        }
        no_token = self.headers
        no_token['Authorization'] = ""
        response = self.client.post(
            '/api/v1/bucketlists',
            data=json.dumps(new_bucketlist),
            headers=no_token)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Authorization Required' in response.data)

    # Update bucketlists tests
    def test_bucketlist_successfully_updated_message(self):
        updates = {
            "name": "the first one",
            "description": "there will be another"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}'.format(
                self.example_bucketlist_one.id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'bucketlist updated successfully'
                        in response.data)

    def test_message_bucketlist_id_does_not_exist(self):
        updates = {
            "name": "the first one",
            "description": "there will be another"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}'.format(89),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'does not exist' in response.data)

    def test_update_bucketlist_request_with_empty_strings(self):
        updates = {
            "name": "",
            "description": "this has no name"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}'.format(
                self.example_bucketlist_one.id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'empty strings not allowed' in response.data)

    # delete bucketlist tests
    def test_bucketlist_deleted_successfully_message(self):
        response = self.client.delete(
            '/api/v1/bucketlists/{}'.format(
                self.example_bucketlist_one.id),
            data={},
            headers=self.headers)
        self.assertTrue(b'bucketlist deleted successfully'
                        in response.data)

    def test_message_for_invalid_bucketlist_id(self):
        response = self.client.delete(
            '/api/v1/bucketlists/{}'.format(21), data={},
            headers=self.headers)
        self.assertTrue(response.status_code == 404)
        self.assertTrue(
            b'cannot delete non-existent bucketlist' in response.data)

    def test_user_bucketlist_is_not_accessed_by_other_user(self):
        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.other_user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])
        response = self.client.get(
            '/api/v1/bucketlists', data={},
            headers=self.headers)
        self.assertFalse(b'bucketlist_one' in response.data)

    def test_user_bucketlist_is_not_deleted_by_other_user(self):
        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.other_user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

        response = self.client.delete(
            '/api/v1/bucketlists/{}'.format(
                self.example_bucketlist_one.id),
            headers=self.headers)
        self.assertEqual(response.status_code, 404)
        self.assertFalse(b'bucketlist deleted successfully'
                         in response.data)
