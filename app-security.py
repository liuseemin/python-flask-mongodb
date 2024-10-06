from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_pymongo import PyMongo
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_talisman import Talisman
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from pymongo.errors import DuplicateKeyError
from flask_wtf.csrf import CSRFProtect
import uuid
import email_validator

from config import Config


app = Flask(__name__)
app.config.from_object(Config)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

# Create Talisman
csp = {
    'default-src': "'self'",
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net'
    ],
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net'
    ],
    'img-src': "'self'"
}
talisman = Talisman(app, content_security_policy=csp)

csrf = CSRFProtect(app)
# csrf.init_app(app)

db = mongo.db

# collection
todos = db.todos
users_collection = db.users

# Login Manager setting
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# define User class
class User(UserMixin):
    def __init__(self, id, username, email, verified, hashed_password) -> None:
        super().__init__()

        self.id = id
        self.username = username
        self.email = email
        self.verified = verified
        self.hashed_password = hashed_password
    
    @classmethod
    def make_from_dict(cls, dict):
        return cls(dict['id'], dict['username'], dict['email'], dict['verified'], dict['hashed_password'])

    def dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'verified': self.verified,
            'hashed_password': self.hashed_password
        }

    def get_id(self):
        return self.id

# Load user from user ID
@login_manager.user_loader
def load_user(userid):
    # find user by userid and omit _id when return
    user = users_collection.find_one({'id': userid}, {'_id': False})
    if user:
        return User.make_from_dict(user)

# Flask-WTF form for user registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = users_collection.find_one({'username': username.data})
        if user:
            raise ValidationError('Username is already taken. Please choose a different one.')

    def validate_email(self, email):
        user = users_collection.find_one({'email': email.data})
        if user:
            raise ValidationError('Email is already registered. Please use a different one.')

# Flask-WTF form for user login
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# home page
@app.route('/', methods=['GET','POST'])
def index():
    if request.method == 'POST':
        content = request.form['content']
        importance = request.form['importance']
        todos.insert_one({'content': content, 'importance': importance})
        return redirect(url_for('index'))
    all_todos = todos.find()
    return render_template('index.html', todos=all_todos)

# Delete item
@app.post('/<id>/delete/')
def delete(id):
    todos.delete_one({"_id": ObjectId(id)})
    return redirect(url_for('index'))

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        logout_user()
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {
            'id': uuid.uuid4().hex, # uuid4().hex is just same without dashes
            'username': form.username.data,
            'email': form.email.data,
            'verified': True,
            'hashed_password': hashed_password
        }
        try:
            # new_user = User.make_from_dict(user_data)
            users_collection.insert_one(user_data)
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except DuplicateKeyError:
            flash('User with this email or username already exists.', 'danger')
    
    return render_template('register.html', form=form)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    # check current user status
    if current_user.is_authenticated:
        flash('You are already logged in!', 'info')
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({'email': form.email.data}, {'_id': False})
        if user and bcrypt.check_password_hash(user['hashed_password'], form.password.data):
            logedin_user = User.make_from_dict(user)
            login_user(logedin_user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)

# Dashboard page
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user.dict()
    return render_template('dashboard.html', username=user['username'])

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# layout test page
@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == "__main__":
    app.run(debug=True)