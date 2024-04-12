#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')

        # Check if username meets criteria
        if not username or len(username) < 4:
            return {'error': 'Username must be at least 4 characters long'}, 422
        if not username.isalnum():
            return {'error': 'Username must contain only letters and numbers'}, 422

        # Check if username is already taken
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'error': 'Username is already taken'}, 422

        # Create new user if username is valid
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return user.to_dict(), 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                # Check if 'id' attribute exists before accessing it
                if hasattr(user, 'id'):
                    return user.to_dict(), 200
                else:
                    return {'error': 'User object does not have an ID attribute'}, 500
            else:
                return {'message': 'User not found'}, 404
        else:
            return {'error': 'No active session'}, 401


            
class Login(Resource):
    def post(self):
        data = request.get_json()
        
        # Check if 'username' field is present in the request data
        if 'username' not in data:
            return {'error': 'Username is missing from the request data'}, 400
        
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return {'error': 'Username or password missing'}, 400

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        
        return {'error': 'Invalid username or password'}, 401

    

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                recipes = Recipe.query.all()
                return {'recipes': [recipe.to_dict() for recipe in recipes]}, 200
            else:
                return {'message': 'User not found'}, 201
        else:
            return {'error': 'Unauthorized'}, 401

    def post(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            if user:
                json = request.get_json()
                title = json.get('title')
                instructions = json.get('instructions')
                minutes_to_complete = json.get('minutes_to_complete')

                if not title or not instructions or not minutes_to_complete:
                    return {'error': 'Title, instructions, or minutes_to_complete missing'}, 400

                recipe = Recipe(
                    title=title,
                    instructions=instructions,
                    minutes_to_complete=minutes_to_complete,
                    user_id=user.id
                )
                db.session.add(recipe)
                db.session.commit()
                return recipe.to_dict(), 201
            else:
                return {'message': 'User not found'}, 404
        else:
            return {'error': 'Unauthorized'}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)