from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from hashlib import md5

from app import db
from app import login


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s{}'.format(digest, size)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(180))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

    def get_duration(self, then, now=datetime.utcnow(), interval="default"):
        # Returns a duration as specified by variable interval
        # Functions, except totalDuration, returns [quotient, remainder]

        duration = now - then  # For build-in functions
        duration_in_s = duration.total_seconds()

        def years():
            return divmod(duration_in_s, 31536000)  # Seconds in a year=31536000.

        def days(seconds=None):
            return divmod(seconds if seconds is not None else duration_in_s, 86400)  # Seconds in a day = 86400

        def hours(seconds=None):
            return divmod(seconds if seconds is not None else duration_in_s, 3600)  # Seconds in an hour = 3600

        def minutes(seconds=None):
            return divmod(seconds if seconds is not None else duration_in_s, 60)  # Seconds in a minute = 60

        def seconds(seconds=None):
            if seconds is not None:
                return divmod(seconds, 1)
            return duration_in_s

        def total_duration():
            y = years()
            d = days(y[1])  # Use remainder to calculate next variable
            h = hours(d[1])
            m = minutes(h[1])
            s = seconds(m[1])

            if int(y[0]) != 0:
                return "{}y ago".format(int(y[0]))
            elif int(d[0]) != 0:
                return "{}d ago".format(int(d[0]))
            elif int(h[0]) != 0:
                return "{}h ago".format(int(h[0]))
            elif int(m[0]) != 0:
                return "{}m ago".format(int(m[0]))
            else:
                return "{}s ago".format(int(s[0]))

            return "Time between dates: {} years, {} days, {} hours, {} minutes and {} seconds".format(int(y[0]),
                                                                                                       int(d[0]),
                                                                                                       int(h[0]),
                                                                                                       int(m[0]),
                                                                                                       int(s[0]))

        return {
            'years': int(years()[0]),
            'days': int(days()[0]),
            'hours': int(hours()[0]),
            'minutes': int(minutes()[0]),
            'seconds': int(seconds()),
            'default': total_duration()
        }[interval]



@login.user_loader
def load_user(id):
    return User.query.get(int(id))
