from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, DateField, RadioField, FieldList, FormField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from db import get_db, mongo

# db = get_db()

db = mongo.db
users_collection = db.users
patients_collection = db.patients

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