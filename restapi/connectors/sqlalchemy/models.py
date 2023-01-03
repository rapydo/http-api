""" Models for the relational database """
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import backref, relationship

from restapi.connectors.sqlalchemy import db

# Define multi-multi relation
roles_users = Table(
    "roles_users",
    db.metadata,
    Column("user_id", Integer, ForeignKey("user.id")),
    Column("role_id", Integer, ForeignKey("role.id")),
)


# Base type Model becomes "Any" due to an unfollowed import
class Role(db):  # type: ignore
    __tablename__ = "role"

    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255), nullable=False)


# Base type Model becomes "Any" due to an unfollowed import
class User(db):  # type: ignore
    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    name = Column(String(255, collation=None), nullable=False)
    surname = Column(String(255, collation=None), nullable=False)
    authmethod = Column(String(20), nullable=False)
    password = Column(String(255), nullable=False)
    mfa_hash = Column(String(255))
    first_login = Column(DateTime(timezone=True))
    last_login = Column(DateTime(timezone=True))
    last_password_change = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    privacy_accepted = Column(Boolean, default=True)
    expiration = Column(DateTime(timezone=True))

    roles = relationship(
        "Role",
        secondary=roles_users,
        backref=backref("users", lazy="dynamic"),  # type: ignore[no-untyped-call]
    )  # type: ignore[var-annotated]
    group_id = Column(Integer, ForeignKey("group.id"))
    belongs_to = relationship(
        "Group",
        backref=backref("members"),  # type: ignore[no-untyped-call]
        foreign_keys=[group_id],
    )  # type: ignore[var-annotated]

    # + has `tokens` backref from Token
    # + has `logins` backref from Login


# Base type Model becomes "Any" due to an unfollowed import
class Token(db):  # type: ignore
    __tablename__ = "token"

    id = Column(Integer, primary_key=True)
    jti = Column(String(36), unique=True, nullable=False)
    token = Column(Text, nullable=False)
    token_type = Column(String(1), nullable=False)
    creation = Column(DateTime(timezone=True), nullable=False)
    expiration = Column(DateTime(timezone=True))
    last_access = Column(DateTime(timezone=True))
    IP = Column(String(46))
    location = Column(String(256))
    user_id = Column(Integer, ForeignKey("user.id"))
    emitted_for = relationship(
        "User", backref=backref("tokens", lazy="dynamic")  # type: ignore[no-untyped-call]
    )  # type: ignore[var-annotated]


# Base type Model becomes "Any" due to an unfollowed import
class Group(db):  # type: ignore
    __tablename__ = "group"

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, nullable=False)
    shortname = Column(String(64), unique=True, nullable=False)
    fullname = Column(String(256), nullable=False)

    # + has `members` backref from User


# Base type Model becomes "Any" due to an unfollowed import
class Login(db):  # type: ignore
    __tablename__ = "login"

    id = Column(Integer, primary_key=True)
    date = Column(DateTime(timezone=True), nullable=False)
    # same length of User.email
    username = Column(String(100))
    IP = Column(String(46))
    location = Column(String(256))
    user_id = Column(Integer, ForeignKey("user.id"), nullable=True)
    user = relationship(
        "User", backref=backref("logins", lazy="dynamic")  # type: ignore[no-untyped-call]
    )  # type: ignore[var-annotated]
    failed = Column(Boolean, default=False)
    flushed = Column(Boolean, default=False)
