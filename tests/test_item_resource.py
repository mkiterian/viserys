from flask_sqlalchemy import SQLAlchemy
import unittest
import json
from passlib.hash import bcrypt

from app import app, db
from app.models import User, Bucketlist, Item
from base_testcase import BaseTest


class ItemResourceTest(BaseTest):
    def setUp(self):
        super(ItemResourceTest, self).setUp()
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
            "bucketlist with items",
            "this is bucketlist has items",
            current_user.id)
        db.session.add(self.example_bucketlist_one)
        db.session.commit()

        self.bucketlist_with_items_id = Bucketlist.query.filter_by(
            name="bucketlist with items").first().id

        self.item_1 = Item('Item one', 'this is item one',
                           self.bucketlist_with_items_id)
        self.item_2 = Item('Item two', 'this is item two',
                           self.bucketlist_with_items_id)
        db.session.add(self.item_1)
        db.session.add(self.item_2)
        db.session.commit()

        self.item_one_id = Item.query.filter_by(
            title='Item one').first().id

        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

    def tearDown(self):
        super(ItemResourceTest, self).tearDown()

    # view items
    def test_item_names_returned_by_view_bucketlists_items(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Item one' in response.data)
        self.assertTrue(b'Item two' in response.data)

    def test_cannot_view_items_without_token(self):
        no_token = self.headers
        no_token['Authorization'] = ""
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            headers=no_token)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Authorization Required' in response.data)

    def test_response_message_for_non_existent_id(self):
        response = self.client.get(
            '/api/v1/bucketlists/2000/items', data={},
            headers=self.headers)
        self.assertTrue(b'bucketlist does not exist' in response.data)

    def test_cannot_view_item_two_when_limit_is_set_to_one(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            query_string=dict(limit='1'),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.count(b'id'), 1)
        self.assertFalse(b'Item two' in response.data)

    def test_item_is_returned_when_q_parameter_is_set(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            query_string=dict(q='two'),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Item two' in response.data)

    def test_item_is_returned_when_page_parameter_is_set(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            query_string=dict(page=1),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Item one' in response.data)

    def test_response_when_page_and_limit_parameter_is_set(self):
        self.headers["Content-Type"] = "None"
        response = self.client.get(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            query_string=dict(page=2, limit=1),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Item two' in response.data)

    # view item
    def test_item_name_returned_when_item_id_is_specified(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(b'Item one' in response.data)

    def test_message_if_item_id_does_not_exist(self):
        response = self.client.get(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, 555),
            headers=self.headers)
        self.assertTrue(b'item does not exist' in response.data)

    # test create item
    def test_item_created_successfully_message(self):
        new_item = {
            "title": "title one",
            "description": "this is my first title"
        }
        response = self.client.post(
            '/api/v1/bucketlists/{}/items'.format(self.item_one_id),
            data=json.dumps(new_item),
            headers=self.headers)
        self.assertTrue(b'item created successfully' in response.data)

    def test_user_cant_add_item_to_other_user_bucketlist(self):
        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.other_user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

        new_item = {
            "title": "not allowed",
            "description": "should not be added"
        }
        response = self.client.post(
            '/api/v1/bucketlists/{}/items'.format(self.item_one_id),
            data=json.dumps(new_item),
            headers=self.headers)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Invalid bucketlist id' in response.data)

    def test_create_item_request_missing_field_message(self):
        new_item = {
            "description": "this is my first title"
        }
        response = self.client.post(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            data=json.dumps(new_item),
            headers=self.headers)
        self.assertTrue(b'Missing required parameter' in response.data)

    def test_create_item_with_empty_strings(self):
        new_item = {
            "title": "",
            "description": "this is my first title"
        }
        response = self.client.post(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            data=json.dumps(new_item),
            headers=self.headers)
        self.assertTrue(b'empty strings not allowed' in response.data)

    def test_cant_create_item_without_authentication(self):
        new_item = {
            "title": "new item title",
            "description": "this is my first title"
        }
        no_token = self.headers
        no_token['Authorization'] = ""
        response = self.client.post(
            '/api/v1/bucketlists/{}/items'.format(
                self.bucketlist_with_items_id),
            data=json.dumps(new_item),
            headers=no_token)
        self.assertTrue(response.status_code == 401)
        self.assertTrue(b'Authorization Required' in response.data)

    # update item
    def test_item_updated_successfully_message(self):
        updates = {
            "title": "not item one anymore",
            "description": "this was changed"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'item updated successfully' in response.data)

    def test_user_cant_update_item_in_other_user_bucketlist(self):
        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.other_user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

        updates = {
            "title": "not allowed",
            "description": "should not be added"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(response.status_code == 404)
        self.assertTrue(b'Invalid bucketlist id' in response.data)

    def test_message_on_update_with_missing_parameter(self):
        updates = {
            "description": "descriptive"
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'Missing required parameter' in response.data)

    def test_message_on_update_with_empty_parameters(self):
        updates = {
            "title": "titular",
            "description": ""
        }
        response = self.client.put(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            data=json.dumps(updates),
            headers=self.headers)
        self.assertTrue(b'empty strings not allowed' in response.data)

    # delete item
    def test_item_successfully_deleted(self):
        response = self.client.delete(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            headers=self.headers)
        self.assertTrue(b'item deleted successfully' in response.data)

    def test_message_for_delete_non_existing_id(self):
        response = self.client.delete(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, 40000),
            headers=self.headers)
        self.assertTrue(b'item does not exist' in response.data)

    def test_user_cant_delete_item_from_other_users_bucketlist(self):
        self.response = self.client.post(
            '/api/v1/auth/login', data=json.dumps(self.other_user),
            headers=self.headers)
        self.response_content = json.loads(self.response.data)
        self.headers['Authorization'] = 'JWT {}'.format(
            self.response_content['access_token'])

        response = self.client.delete(
            '/api/v1/bucketlists/{}/items/{}'.format(
                self.bucketlist_with_items_id, self.item_one_id),
            headers=self.headers)
        self.assertTrue(response.status_code == 404)
        self.assertTrue(b'Invalid bucketlist id' in response.data)
