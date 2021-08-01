from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Length
from app.models import User


class LoginForm(FlaskForm):
    '''
    Provides the "Login" related fields, so a user can enter the data and login.
    '''
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    '''
    Provides Registration related fields on the Web App, so a user can
    register.
    '''
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class EditProfileForm(FlaskForm):
    '''
    Provides the fields so that the editing of ones profile can be facilitated.
    'about_me', 'username' can be edited.
    '''
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')

class EmptyForm(FlaskForm):
    '''
    For 'following', 'unfollowing' purposes; the class provides empty forms for
    users.
    '''
    submit = SubmitField('Submit')


class ResetPasswordRequestForm(FlaskForm):
    '''
    Upon clicking for 'Click for Password Reset!', A form will show
    with the below fields.
    '''
    email = StringField('Email', validators = [DataRequired()])
    submit = SubmitField('Reset Password Request')


class PostForm(FlaskForm):
    '''
    On the Index/Home Page, the PostForm will be shown, from where a user
    can post, a post.
    '''
    post = TextAreaField('Say Something', validators = [
    DataRequired(), Length(min = 1, max = 150)
    ])
    submit = SubmitField('Submit')

class ResetPasswordForm(FlaskForm):
    '''
    When a user clicks on the link emailed, the defined form will show.
    '''
    password = PasswordField('Password', validators = [DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators = [DataRequired(), EqualTo('password')])
    submit = SubmitField('Submit')
