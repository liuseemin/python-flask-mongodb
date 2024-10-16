from flask_pymongo import PyMongo
from flask import current_app, g

mongo = PyMongo()

def init_db(app):
    mongo.init_app(app)
    return mongo.db

def get_db():
    return mongo.db