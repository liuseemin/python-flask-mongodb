from flask import Flask, jsonify, render_template, url_for, request, redirect, flash, session
from flask_pymongo import PyMongo
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_talisman import Talisman
# from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import BooleanField, DateField, FieldList, FormField, RadioField, SelectField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from pymongo.errors import DuplicateKeyError
from flask_wtf.csrf import CSRFProtect
import uuid
import email_validator
from datetime import datetime

# import patient structure
from patient import Patient
from patient_data import Problem, admission, gi_status

from config import Config

app = Flask(__name__)
app.config.from_object(Config)
bcrypt = Bcrypt(app)
mongo = PyMongo(app)

# Safety setting
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
    'img-src': [
        "'self'",
        'https:',
        'data:'
    ]
}
talisman = Talisman(app, content_security_policy=csp)

# CSRF setting
csrf = CSRFProtect(app)

# database and collections
db = mongo.db
todos = db.todos
users_collection = db.users
patients_collection = db.patients
problem_colection = db.problems
log_collection = db.logs

# Log method
def logger(category, action, user, target, message):
    log = {
        'category': category,
        'action': action,
        'user': user,
        'target': target,
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    log_collection.insert_one(log)

# Login Manager setting
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"


# custom unauthorized handler
@login_manager.unauthorized_handler
def unauthorized():
    logger('danger','Unauthorized', 'None', 'None', 'Unauthorized access')
    flash('You must be logged in to access this page.', 'danger')
    return redirect(url_for('login'))

# define User class
class User(UserMixin):
    def __init__(self, id, username, email, verified, hashed_password, role) -> None:
        super().__init__()

        self.id = id
        self.username = username
        self.email = email
        self.verified = verified
        self.hashed_password = hashed_password
        self.role = role
    
    @classmethod
    def make_from_dict(cls, dict):
        if dict.get('role') == None:
            dict['role'] = 'user'
        return cls(dict['id'], dict['username'], dict['email'], dict['verified'], dict['hashed_password'], dict['role'])

    def dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'verified': self.verified,
            'hashed_password': self.hashed_password,
            'role': self.role
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


#=====================================================

# Flask-WTF form for user registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=20)])
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

# problem form
class problem_form(FlaskForm):
    problem_id = StringField('Problem ID', validators=[DataRequired()])
    title = StringField('Title', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    active = BooleanField('Active')
    start = DateField('Start', format='%Y-%m-%d')
    end = DateField('End', format='%Y-%m-%d')

# Add-patient form (dynamic), may change to other file and import it for code clarity
class AddPatientFormDynamic(FlaskForm):
    id = StringField('ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    age = StringField('Age', validators=[DataRequired()])
    problems = FieldList(FormField(problem_form), min_entries=1)

    submit = SubmitField('Add Patient')

    def validate_id(self, id):
        patient = patients_collection.find_one({'id': id.data})
        if patient:
            raise ValidationError('Patient with this ID is already registered. Please use edit instead.')
        
# Add-patient form
class AddPatientForm(FlaskForm):
    id = StringField('ID', validators=[DataRequired()])
    name = StringField('Name', validators=[DataRequired()])
    age = StringField('Age', validators=[DataRequired()])
    sex = RadioField('Sex', choices=[('M', 'Male'), ('F', 'Female')])

    submit = SubmitField('Add Patient')

    def validate_id(self, id):
        patient = patients_collection.find_one({'id': id.data})
        if patient:
            raise ValidationError('Patient with this ID is already registered!')

#=====================================================

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
            'verified': False,
            'hashed_password': hashed_password,
            'role': 'user'
        }
        try:
            # new_user = User.make_from_dict(user_data)
            users_collection.insert_one(user_data)
            flash('Account created successfully', 'success')
            logger('success','Account created', user_data['username'], user_data['username'], 'Account created successfully')
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
            if user['verified'] == False:
                flash('Unverified account. Please contact admin to verify your account.', 'danger')
                return render_template('login.html', form=form)
            logedin_user = User.make_from_dict(user)
            login_user(logedin_user)
            flash('Login successful!', 'success')
            logger('primary','Login', logedin_user.username, 'None', 'Login successful')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html', form=form)

# Dashboard page
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user.dict()
    return render_template('dashboard.html', username=user['username'], role=user['role'])

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Patient list
@app.route('/patients')
@login_required
def patients():
    patients = patients_collection.find()
    return render_template('patients.html', patients=patients)

# Patient details
@app.route('/patient/<id>')
@login_required
def patient(id):
    patient = patients_collection.find_one({'id': id})
    return render_template('patient.html', patient=patient)

# Add patient simple
@app.route('/patient/add', methods=['GET', 'POST'])
@login_required
def add_patient():
    form = AddPatientForm()
    if form.validate_on_submit():
        patient_data = {
            'id': form.id.data,
            'name': form.name.data,
            'age': form.age.data,
            'sex': form.sex.data,
            'problems': [],
            'OP_hx': '',
            'GI_status': None,
            'lab': {},
            'notes': '',
            'admission_hx': None
        }
        patients_collection.insert_one(patient_data)
        logger('success','Add new patient', current_user.username, patient_data['name'], 'Patient added successfully')
        flash('Patient added successfully', 'success')
        return redirect(url_for('patients'))

    return render_template('add-patient.html', form=form)

# Add problem form dynamically
@app.route('/add-field', methods=['POST'])
@login_required
def add_field():
    # Add new field for AJAX response
    new_field_html = render_template('field-problem.html', field_id=request.form['field_id'])
    return jsonify({'new_field': new_field_html})

# delete patient
@app.route('/patient/<id>/delete')
@login_required
def delete_patient(id):
    pass

# log page
@app.route('/log')
@login_required
def log():
    logs = log_collection.find()
    return render_template('log.html', logs=logs)

# clear logs
@app.route('/clear_logs')
@login_required
def clear_logs():
    log_collection.delete_many({})
    return redirect(url_for('log'))

# admin dashboard page
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('dashboard'))
    users = users_collection.find()
    return render_template('admin.html', users=users) 

# Handle change role
@app.route('/change-role', methods=['POST'])
@login_required
def change_role():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('dashboard'))
    role = request.form['role']
    id = request.form['user_id']
    admin_count = users_collection.count_documents({'role': 'admin'})
    if (id == current_user.id and role != 'admin' and admin_count == 1):
        flash('You cannot remove the last admin', 'danger')
        return redirect(url_for('admin'))

    users_collection.update_one({'id': id}, {'$set': {'role': role}})
    flash('Role changed successfully', 'success')
    logger('success', 'role changed', current_user.username, users_collection.find_one({'id': id})['username'], 'Role changed successfully')
    return redirect(url_for('admin'))

# delete user
@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('dashboard'))
    id = request.form['user_id']
    username = users_collection.find_one({'id': id})['username']
    admin_count = users_collection.count_documents({'role': 'admin'})
    if (id == current_user.id and admin_count == 1):
        flash('You cannot delete the last admin', 'danger')
        return redirect(url_for('admin'))
    users_collection.delete_one({'id': id})
    flash('User deleted successfully', 'success')
    logger('danger', 'user deleted', current_user.username, username, 'User deleted successfully')
    return redirect(url_for('admin'))

# Verify user
@app.route('/verify_user')
@login_required
def verify_user():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('dashboard'))
    id = request.args.get('id')
    user = users_collection.find_one({'id': id})
    action = 'verified'
    valueTo = True
    if user['verified'] and user['role'] != 'admin':
        action = 'unverified'
        valueTo = False
    users_collection.update_one({'id': id}, {'$set': {'verified': valueTo}})
    flash('User ' + action + ' successfully', 'success')
    logger('success', 'user ' + action, current_user.username, users_collection.find_one({'id': id})['username'], 'User ' + action + ' successfully')
    return redirect(url_for('admin'))

# layout test page
@app.route('/test')
def test():
    return render_template('test.html')


if __name__ == "__main__":
    app.run(debug=True)