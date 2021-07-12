from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from app import db, login, app
from hashlib import md5
from time import time
import jwt




# Below, is the association table between a 'User' table and itself.
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
    )

# Below given is the 'User' table/model/class in the datase of our Web App.
class User(UserMixin, db.Model):
    '''
    The 'User' model/table/class is a table of our database which stores the fields
    such as username, email, hashed version of password, about_me, last_seen.
    '''

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(64), index=True, unique=True)

    email = db.Column(db.String(120), index=True, unique=True)

    password_hash = db.Column(db.String(128))

    about_me = db.Column(db.String(140))

    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    # Below, statement is the relationship between 'User' Model
    # and 'Post' model of the dtaabase. It is one-to-many relationship.
    posts = db.relationship('Post', backref='author', lazy='dynamic')


    # Below, defines the relationship between a User table with itself ihich is
    # self-refferential. As a User follows many users and vice versa.
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')


    # user.set_password() would set password_hash for the i/p password.
    def set_password(self, password):
        '''
        The password entered by the user will be convereted inton its hashed version
        using this method, and then stored in the database.
        '''
        self.password_hash = generate_password_hash(password)


    # When the user logs in, the entered password is checked with the
    # database password, and at that time, the below method is used.
    def check_password(self, password):
        '''
        The user entered password to login can be checked to find if it is true in the backend,
        using this method.
        '''
        return check_password_hash(self.password_hash, password)

    # Below, method returns a link which posts an image.
    def avatar(self, size):
        '''
        This function returns a 'link' that will display the gravatar image of the user.
        And, a by default image if it is not present.
        '''
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)


    def follow(self, user):
        '''
        When a user follows another user on the Web App, we can recreate
        the same scenario in the database,by invoking this method with the user's
        object and passing the user who is followed, as an argument.
        '''
        if not self.is_following(user):
            self.followed.append(user)


    def unfollow(self, user):
        '''
        When a user unfollows another user on the Web App, we can recreate
        the same scenario in the database,by invoking this method with the user's
        object and passing the user who is unfollowed, as an argument.
        '''
        if self.is_following(user):
            self.followed.remove(user)


    def is_following(self, user):
        '''
        Thi function checks if a user is already following a particular user.
        '''
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0


    def followed_posts(self):
        '''
        This method will return all the posts of the user itself and the users that
        he/she follows, in descending order(i.e. most recent to late).
        '''
        followed = Post.query.join(
          followers, (followers.c.followed_id == Post.user_id)).filter(
            followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())


    def get_reset_password_token(self, expires_in=600):
        '''
        This method is used to generate a password token sent to the users.
        '''
        return jwt.encode(
                {'reset_password' : self.id,'exp': time() + expires_in},
                app.config['SECRET_KEY'], algorithm = 'HS256')


    @staticmethod
    def verify_password_token(token):
        '''
        This method is used for verifying if the token is valid. Hence, we need to
        decode the token.
        '''
        try:
            id = jwt.decode(token,
                       app.config['SECRET_KEY'], algorithms = ['HS256'])['reset_password']
        except:
            # If the token is invalid, then 'None' will be returned.
            return
        # If the token is valid, then the 'user' object is returned.
        return User.query.get(id)


    # Dunder method. Each 'User' object is represented by the __repr__() below.
    def __repr__(self):
        return '<User {}>'.format(self.username)


@login.user_loader
def load_user(id):
    return User.query.get(int(id))



class Post(db.Model):
    '''
    The 'Post' table/model/class has various fields for a user stored such as,
    post's body, title and time of posting.
    '''
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    # Below, is the foreignkey of 'User' table.
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Dunder method! Each 'Post' object is represented by __repr__ below.
    def __repr__(self):
        return '<Post {}>'.format(self.body)
