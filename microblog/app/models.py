from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import UserMixin
from app import db, login
from hashlib import md5




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
        self.password_hash = generate_password_hash(password)

    # When the user logs in, the entered password is checked with the
    # database password, and at that time, the below method is used.
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Below, method returns a link which posts an image.
    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Post.query.join(
          followers, (followers.c.followed_id == Post.user_id)).filter(
            followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())


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
