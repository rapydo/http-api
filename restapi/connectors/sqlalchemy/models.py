""" Models for the relational database """
import os

from restapi.connectors.sqlalchemy import db

if os.getenv("ALCHEMY_DBTYPE") == "mysql+pymysql":
    # Required by MySQL to accept unicode strings (like chinese)
    DEFAULT_COLLATION = "utf8_unicode_ci"
else:
    DEFAULT_COLLATION = None

####################################
# Define multi-multi relation
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)


####################################
# Define models
class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(255, collation=DEFAULT_COLLATION))
    surname = db.Column(db.String(255, collation=DEFAULT_COLLATION))
    authmethod = db.Column(db.String(20))
    password = db.Column(db.String(255))
    first_login = db.Column(db.DateTime(timezone=True))
    last_login = db.Column(db.DateTime(timezone=True))
    last_password_change = db.Column(db.DateTime(timezone=True))
    is_active = db.Column(db.Boolean, default=True)
    privacy_accepted = db.Column(db.Boolean, default=True)
    roles = db.relationship(
        "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
    )

    # + has `belongs_to` backref from Group
    # + has `coordinator_for` backref from Group


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True)
    # token = db.Column(db.String(360), unique=True)
    token = db.Column(db.Text())
    token_type = db.Column(db.String(1))
    creation = db.Column(db.DateTime(timezone=True))
    expiration = db.Column(db.DateTime(timezone=True))
    last_access = db.Column(db.DateTime(timezone=True))
    IP = db.Column(db.String(46))
    # no longer used
    hostname = db.Column(db.String(256))
    location = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    emitted_for = db.relationship("User", backref=db.backref("tokens", lazy="dynamic"))


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True)
    shortname = db.Column(db.String(64), unique=True)
    fullname = db.Column(db.String(256))

    members = db.relationship("User", backref="belongs_to")

    coordinator_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    coordinator = db.relationship(
        "User", backref=db.backref("coordinator_for", uselist=False)
    )
