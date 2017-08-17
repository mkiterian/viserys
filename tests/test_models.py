from unittest import TestCase
from app import app, db
from app.models import User, Bucketlist, Item


class UserTestCase(TestCase):

    def setUp(self):
        app.config.from_object('config.TestingConfig')
        db.drop_all()
        db.create_all()
        self.user = User('homer', 'homer@gmail.com', 'secret')
        db.session.add(self.user)
        db.session.commit

    def tearDown(self):
        db.session.remove()

    def test_user_successfully_added_to_db(self):
        user = User.query.filter_by(username='homer').first()
        self.assertTrue(self.user.id)

    def test_user_has_bucketlist_property(self):
        self.assertTrue(hasattr(self.user, 'bucketlists'))

    def test_user_id_is_set(self):
        user = User.query.filter_by(username='homer').first()
        self.assertEqual(str(self.user), "User(id='1')")


class BucketlistTestCase(TestCase):
    def setUp(self):
        self.bucketlist = Bucketlist('Vacationing', 'Go places', 100)

    def test_bucketlist_has_item_property(self):
        self.assertTrue(hasattr(self.bucketlist, 'items'))

    def test_bucketlist_name_is_set(self):
        self.assertEqual(str(self.bucketlist),
                         "Bucketlist(name='Vacationing')")


class ItemTestCase(TestCase):
    def setUp(self):
        self.item = Item('Go to Egypt', 'It\'s a pyramid scheme', 100)

    def test_item_has_been_created(self):
        self.assertEqual(str(self.item.title), 'Go to Egypt')

    def test_item_title_is_set(self):
        self.assertEqual(str(self.item), "Item(title='Go to Egypt')")
