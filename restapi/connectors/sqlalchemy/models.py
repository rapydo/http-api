""" Models for the relational database """
from restapi.connectors.sqlalchemy import SQLAlchemy, db

DEFAULT_COLLATION = None
if SQLAlchemy.is_mysql():
    # Required by MySQL to accept unicode strings (like chinese)
    DEFAULT_COLLATION = "utf8_unicode_ci"

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
    mfa_hash = db.Column(db.String(255))
    first_login = db.Column(db.DateTime(timezone=True))
    last_login = db.Column(db.DateTime(timezone=True))
    last_password_change = db.Column(db.DateTime(timezone=True))
    is_active = db.Column(db.Boolean, default=True)
    privacy_accepted = db.Column(db.Boolean, default=True)
    expiration = db.Column(db.DateTime(timezone=True))

    roles = db.relationship(
        "Role", secondary=roles_users, backref=db.backref("users", lazy="dynamic")
    )
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"))
    belongs_to = db.relationship(
        "Group", backref=db.backref("members"), foreign_keys=[group_id]
    )


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

    # + has `members` backref from User
