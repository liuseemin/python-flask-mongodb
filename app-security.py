from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_pymongo import PyMongo
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_talisman import Talisman
from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from pymongo.errors import DuplicateKeyError
from flask_wtf.csrf import CSRFProtect
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
    ]
}
talisman = Talisman(app, content_security_policy=csp)

csrf = CSRFProtect(app)
# csrf.init_app(app)

db = mongo.db

# collection
todos = db.todos
users_collection = db.users

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
    todos.delete_one({"_id":ObjectId(id)})
    return redirect(url_for('index'))

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user_data = {
            'username': form.username.data,
            'email': form.email.data,
            'password': hashed_password
        }
        try:
            users_collection.insert_one(user_data)
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except DuplicateKeyError:
            flash('User with this email or username already exists.', 'danger')
    
    return render_template('register.html', form=form)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        flash('You are already logged in!')
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = users_collection.find_one({'email': form.email.data})
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            session['user_id'] = str(user['_id'])
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)

# Dashboard page
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('dashboard.html', username=user['username'])

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# layout test page
@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == "__main__":
    app.run(debug=True)