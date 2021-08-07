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

# Base type Model becomes "Any" due to an unfollowed import# Define models
class Role(db.Model):  # type: ignore
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)


# Base type Model becomes "Any" due to an unfollowed import
class User(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(255, collation=DEFAULT_COLLATION), nullable=False)
    surname = db.Column(db.String(255, collation=DEFAULT_COLLATION), nullable=False)
    authmethod = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(255), nullable=False)
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

    # + has `tokens` backref from Token
    # + has `logins` backref from Login


# Base type Model becomes "Any" due to an unfollowed import
class Token(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    # token = db.Column(db.String(360), unique=True)
    token = db.Column(db.Text(), nullable=False)
    token_type = db.Column(db.String(1), nullable=False)
    creation = db.Column(db.DateTime(timezone=True), nullable=False)
    expiration = db.Column(db.DateTime(timezone=True))
    last_access = db.Column(db.DateTime(timezone=True))
    IP = db.Column(db.String(46))
    location = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    emitted_for = db.relationship("User", backref=db.backref("tokens", lazy="dynamic"))


# Base type Model becomes "Any" due to an unfollowed import
class Group(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(36), unique=True, nullable=False)
    shortname = db.Column(db.String(64), unique=True, nullable=False)
    fullname = db.Column(db.String(256), nullable=False)

    # + has `members` backref from User


# Base type Model becomes "Any" due to an unfollowed import
class Login(db.Model):  # type: ignore
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime(timezone=True), nullable=False)
    # same length of User.email
    username = db.Column(db.String(100))
    IP = db.Column(db.String(46))
    location = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    user = db.relationship("User", backref=db.backref("logins", lazy="dynamic"))
    failed = db.Column(db.Boolean, default=False)
    flushed = db.Column(db.Boolean, default=False)
