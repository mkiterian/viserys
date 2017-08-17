from passlib.hash import bcrypt

from flask import jsonify, json, request
from flask_jwt import JWT, jwt_required, current_identity
from flask_restful import (Api, Resource, abort,
                           fields, marshal, reqparse)

from app import app, db
from .models import Bucketlist, Item, User

api = Api(app, prefix='/api/v1')


def verify(username, password):
    if not (username and password):
        return False
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.verify(password, user.password):
        return user
    return False


def identity(payload):
    user_id = payload['identity']
    return {"user_id": user_id}


jwt = JWT(app, verify, identity)


class UserResource(Resource):
    '''
    Defines handlers for get, post and put user requests
    '''

    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str,
                            required=True, location='json')
        parser.add_argument('email', type=str, required=True,
                            location='json')
        parser.add_argument('password', type=str,
                            required=True, location='json')
        parser.add_argument('confirm_password', type=str,
                            required=True, location='json')

        args = parser.parse_args(strict=True)
        if args['username']:
            if args['email']:
                if args['password'] == args['confirm_password']:
                    hash = bcrypt.hash(args['password'], rounds=12)
                    user = User(args['username'],
                                args['email'], hash)
                    db.session.add(user)
                    db.session.commit()
                    return {
                        'message': 'user successfully registered!'
                    }, 201
                return {'message': 'password should match '
                        'confirm password'}, 400
            return {'message': 'email is required'}, 400
        return {'message': 'username is required'}, 400


class BucketlistResource(Resource):
    '''
    Defines handlers for get, post and put bucketlist requests
    '''
    @jwt_required()
    def get(self, id=None):
        bucketlist_fields = {
            'id': fields.Integer,
            'name': fields.String,
            'description': fields.String
        }

        if id is not None:
            bucketlist = Bucketlist.query.filter_by(
                owner_id=current_identity['user_id'],
                id=id).first()
            if bucketlist is not None:
                return marshal(bucketlist, bucketlist_fields)
            return {'message': 'requested id does not exist'}, 404
        if request.args:
            parser = reqparse.RequestParser()
            parser.add_argument('page',
                                type=int,
                                default=1,
                                location='args')
            parser.add_argument('limit',
                                type=int,
                                default=10,
                                location='args')
            parser.add_argument('q',
                                type=str,
                                location='args')
            args = parser.parse_args(strict=True)

            if args['q']:
                result = Bucketlist.query.filter(
                    Bucketlist.owner_id == (
                        current_identity['user_id']),
                    Bucketlist.name.contains(args['q'])
                ).order_by(Bucketlist.id.asc())

                if int(args['page']) > (
                        len(result.all()) / int(args['limit']) + 1
                ) or int(args['page']) < 1:
                    return {'message': 'Page does not exist'}, 404

                bucketlists = result.paginate(
                    args['page'],
                    args['limit'],
                    error_out=False)

                if len(bucketlists.items) < 1:
                    return {
                        'message': 'Bucketlist does not exist'
                    }, 404

            result = Bucketlist.query.filter(
                Bucketlist.owner_id == (
                    current_identity['user_id'])
            ).order_by(
                Bucketlist.id.asc())

            if int(args['page']) > (
                    len(result.all()) / int(args['limit']) + 1
            ) or int(args['page']) < 1:
                return {'message': 'Page does not exist'}, 404

            bucketlists = result.paginate(
                args['page'],
                args['limit'],
                error_out=False)

            return {
                "count": len(bucketlists.items),
                "next": "/api/v1/bucketlists?page={}&limit={}"
                .format(args['page'] + 1, args['limit']),
                "previous": "/api/v1/bucketlists?page={}&limit={}"
                .format(args['page'] - 1, args['limit']),
                "bucketlists": marshal(bucketlists.items,
                                        bucketlist_fields)}, 200

        bucketlists = Bucketlist.query.order_by(
            Bucketlist.id.asc()).filter_by(
            owner_id=current_identity['user_id']).all()
        return {"bucketlists": marshal(bucketlists,
                                        bucketlist_fields)}, 200

    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name',
                            type=str, required=True, location='json')
        parser.add_argument('description', type=str,
                            required=True, location='json')

        args = parser.parse_args(strict=True)
        if len(args['name'].strip()) == 0 or len(
                args['description'].strip()) == 0:
            return {'message': 'empty strings not allowed'}, 400

        new_bucketlist = Bucketlist(
            args['name'], args['description'],
            current_identity['user_id'])
        db.session.add(new_bucketlist)
        db.session.commit()

        return {'message': 'bucketlist created successfully'}, 201

    @jwt_required()
    def put(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('name',
                            type=str, required=True, location='json')
        parser.add_argument('description', type=str,
                            required=True, location='json')

        args = parser.parse_args(strict=True)

        bucketlist = Bucketlist.query.filter_by(
            owner_id=current_identity['user_id'],
            id=id).first()
        if bucketlist:
            if len(args['name'].strip()) == 0 or len(
                    args['description'].strip()) == 0:
                return {'message': 'empty strings not allowed'}, 400

            bucketlist.name = args['name']
            bucketlist.description = args['description']

            db.session.merge(bucketlist)
            db.session.commit()
            return {
                'message': 'bucketlist updated successfully'
            }, 200

        return {'message': 'does not exist'}, 404

    @jwt_required()
    def delete(self, id):
        bucketlist = Bucketlist.query.filter_by(
            owner_id=current_identity['user_id'],
            id=id).first()
        if bucketlist is not None:
            db.session.delete(bucketlist)
            db.session.commit()
            return {'message': 'bucketlist deleted successfully'}, 200

        return {
            'message': 'cannot delete non-existent bucketlist'
        }, 404


class ItemResource(Resource):
    '''
    handles get, post, put and delete item requests
    '''
    @jwt_required()
    def get(self, id, item_id=None):
        bucketlist = Bucketlist.query.filter_by(
            id=id,
            owner_id=current_identity['user_id']
        ).first()

        item_fields = {
            'id': fields.Integer,
            'title': fields.String,
            'description': fields.String
        }

        if bucketlist is not None:
            if item_id is not None:
                item = Item.query.filter_by(bucket_id=bucketlist.id,
                                            id=item_id).first()
                if item:
                    return marshal(item, item_fields), 200

                return {'message': 'item does not exist'}, 404

            if request.args:
                parser = reqparse.RequestParser()
                parser.add_argument('page',
                                    type=int,
                                    default=1,
                                    location='args')
                parser.add_argument('limit',
                                    type=int,
                                    default=10,
                                    location='args')
                parser.add_argument('q',
                                    type=str,
                                    location='args')
                args = parser.parse_args(strict=True)

                if args['q']:
                    result = Item.query.filter(
                        Item.bucket_id == bucketlist.id,
                        Item.title.contains(args['q'])
                    ).order_by(
                        Item.id.asc())

                    if int(args['page']) > (
                            len(result.all()) / int(args['limit']) + 1
                    ) or int(args['page']) < 1:
                        return {'message': 'Page does not exist'}, 404

                    items = result.paginate(
                        args['page'],
                        args['limit'],
                        error_out=False)

                    if len(items.items) < 1:
                        return {
                            'message': 'Item does not exist'
                        }, 404

                result = Item.query.filter(
                    Item.bucket_id == bucketlist.id
                ).order_by(Item.id.asc())

                if int(args['page']) > (
                        len(result.all()) / int(
                            args['limit']) + 1
                ) or int(args['page']) < 1:
                    return {
                        'message': 'Page does not exist'
                    }, 404

                items = result.paginate(
                    args['page'],
                    args['limit'],
                    error_out=False)

                return {
                    "count": len(items.items),
                    "next": "/api/v1/bucketlists/{}"
                    "/items?page={}&limit={}"
                    .format(id, args['page'] + 1, args['limit']),
                    "previous": "/api/v1/bucketlists/{}"
                    "/items?page={}&limit={}"
                    .format(id, args['page'] - 1, args['limit']),
                    "items": marshal(items.items,
                                        item_fields)}, 200

            items = Item.query.filter(
                Item.bucket_id == bucketlist.id
            ).order_by(Item.id.asc()).all()

            return {"items": marshal(items, item_fields)}, 200

        return {'message': 'bucketlist does not exist'}, 404

    @jwt_required()
    def post(self, id):
        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str,
                            required=True, location='json')
        parser.add_argument('description', type=str,
                            required=True, location='json')

        args = parser.parse_args(strict=True)
        if len(args['title'].strip()) == 0 or len(
                args['description'].strip()) == 0:
            return {'message': 'empty strings not allowed'}, 400

        bucketlist = Bucketlist.query.filter_by(
            id=id,
            owner_id=current_identity['user_id']
        ).first()
        if bucketlist:
            new_item = Item(args['title'], args['description'],
                            bucketlist.id)
            db.session.add(new_item)
            db.session.commit()
            return {'message': 'item created successfully'}, 201

        return {
            'message': 'Invalid bucketlist id'
        }, 401

    @jwt_required()
    def put(self, id, item_id):
        bucketlist = Bucketlist.query.filter_by(
            id=id,
            owner_id=current_identity['user_id']
        ).first()

        parser = reqparse.RequestParser()
        parser.add_argument('title', type=str,
                            required=True, location='json')
        parser.add_argument('description', type=str,
                            required=True, location='json')

        args = parser.parse_args(strict=True)

        if bucketlist:
            item = Item.query.filter_by(
                id=item_id, bucket_id=bucketlist.id).first()
            if item:
                if len(args['title'].strip()) == 0 or len(
                        args['description'].strip()) == 0:
                    return {
                        'message': 'empty strings not allowed'
                    }, 400

                item.title = args['title']
                item.description = args['description']
                db.session.merge(item)
                db.session.commit()
                return {
                    'message': 'item updated successfully'
                }, 200

            return {'message': 'item does not exist'}, 404

        return {'message': 'Invalid bucketlist id'}, 404

    @jwt_required()
    def delete(self, id, item_id):
        bucketlist = Bucketlist.query.filter_by(
            id=id,
            owner_id=current_identity['user_id']
        ).first()
        if bucketlist:
            item = Item.query.filter_by(
                id=item_id, bucket_id=bucketlist.id).first()
            if item:
                db.session.delete(item)
                db.session.commit()
                return {'message': 'item deleted successfully'}, 200

            return {
                'message': 'cannot delete, item does not exist'
            }, 404

        return {'message': 'Invalid bucketlist id'}, 404


api.add_resource(UserResource, '/auth/register')
api.add_resource(BucketlistResource,
                 '/bucketlists/<int:id>', '/bucketlists')
api.add_resource(ItemResource,
                 '/bucketlists/<int:id>/items/<item_id>',
                 '/bucketlists/<int:id>/items')
