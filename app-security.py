from flask import Flask, jsonify, render_template, url_for, request, redirect, flash, session
from flask_pymongo import PyMongo
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_talisman import Talisman
# from pymongo.server_api import ServerApi
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import BooleanField, DateField, FieldList, FormField, StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Email, ValidationError
from pymongo.errors import DuplicateKeyError
from flask_wtf.csrf import CSRFProtect
import uuid
import email_validator
from datetime import datetime
from patientForm import AddPatientForm

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
    'img-src': "'self'"
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

    submit = SubmitField('Add Patient')

    def validate_id(self, id):
        patient = patients_collection.find_one({'id': id.data})
        if patient:
            raise ValidationError('Patient with this ID is already registered. Please use edit instead.')

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
            'verified': True,
            'hashed_password': hashed_password,
            'role': 'user'
        }
        try:
            # new_user = User.make_from_dict(user_data)
            users_collection.insert_one(user_data)
            flash('Account created successfully', 'success')
            logger('primary','Account created', user_data['username'], 'None', 'Account created successfully')
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
            logger('primary','Login', logedin_user.username, 'None', 'Login successful')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')

    return render_template('login.html', form=form)

# Dashboard page
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user.dict()
    return render_template('dashboard.html', username=user['username'], role=user['role'])

# admin dashboard page
@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('admin.html')

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

    return render_template('add-patient.html', form=form)

# Add patient with dynamic fields (problem)
@app.route('/patient/add-dynamic', methods=['GET', 'POST'])
@login_required
def add_patient_dynamic():
    form = AddPatientForm()
    if form.validate_on_submit():
        problems = []
        for problem_form in form.problems:
            problem_data = {
                'problem_id': problem_form.problem_id.data,
                'title': problem_form.title.data,
                'description': problem_form.description.data,
                'active': problem_form.active.data,
                'start': problem_form.start.data,
                'end': problem_form.end.data,
                'link': ''
            }
            problems.append(Problem.make_from_dict(problem_data))
        
        patient_data = {
            'id': form.id.data,
            'name': form.name.data,
            'age': form.age.data,
            'problems': problems,
            'OP_hx': '',
            'GI_status': None,
            'lab': {},
            'notes': '',
            'admission_hx': None
        }
        patients_collection.insert_one(patient_data)
        logger('success','Add new patient', current_user.username, patient_data['name'], 'Patient added successfully')
        flash('Patient added successfully', 'success')

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

# layout test page
@app.route('/test')
def test():
    return render_template('test.html')

if __name__ == "__main__":
    app.run(debug=True)