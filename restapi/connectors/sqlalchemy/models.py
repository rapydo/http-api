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
from sqlalchemy.orm import DeclarativeBase, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# Define multi-multi relation
roles_users = Table(
    "roles_users",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("user.id")),
    Column("role_id", Integer, ForeignKey("role.id")),
)


class Role(Base):
    __tablename__ = "role"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id}, {self.name})"

    id = mapped_column(Integer, primary_key=True)
    name = mapped_column(String(80), unique=True, nullable=False)
    description = mapped_column(String(255), nullable=False)

    users = relationship(
        "User",
        secondary=roles_users,
        back_populates="roles",
        cascade_backrefs=False,
    )


class User(Base):
    __tablename__ = "user"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id}, {self.email})"

    id = mapped_column(Integer, primary_key=True)
    uuid = mapped_column(String(36), unique=True, nullable=False)
    email = mapped_column(String(100), unique=True, nullable=False)
    name = mapped_column(String(255, collation=None), nullable=False)
    surname = mapped_column(String(255, collation=None), nullable=False)
    authmethod = mapped_column(String(20), nullable=False)
    password = mapped_column(String(255), nullable=False)
    mfa_hash = mapped_column(String(255))
    first_login = mapped_column(DateTime(timezone=True))
    last_login = mapped_column(DateTime(timezone=True))
    last_password_change = mapped_column(DateTime(timezone=True))
    is_active = mapped_column(Boolean, default=True)
    privacy_accepted = mapped_column(Boolean, default=True)
    expiration = mapped_column(DateTime(timezone=True))

    roles = relationship(
        "Role",
        secondary=roles_users,
        back_populates="users",
    )
    group_id = mapped_column(Integer, ForeignKey("group.id"))
    belongs_to = relationship(
        "Group",
        back_populates="members",
        cascade_backrefs=False,
        foreign_keys=[group_id],
    )
    tokens = relationship(
        "Token",
        back_populates="emitted_for",
        cascade_backrefs=False,
    )
    logins = relationship(
        "Login",
        back_populates="user",
        cascade_backrefs=False,
    )


class Token(Base):
    __tablename__ = "token"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id})"

    id = mapped_column(Integer, primary_key=True)
    jti = mapped_column(String(36), unique=True, nullable=False)
    token = mapped_column(Text, nullable=False)
    token_type = mapped_column(String(1), nullable=False)
    creation = mapped_column(DateTime(timezone=True), nullable=False)
    expiration = mapped_column(DateTime(timezone=True))
    last_access = mapped_column(DateTime(timezone=True))
    IP = mapped_column(String(46))
    location = mapped_column(String(256))
    user_id = mapped_column(Integer, ForeignKey("user.id"))
    emitted_for = relationship(
        "User",
        back_populates="tokens",
        cascade_backrefs=False,
    )


class Group(Base):
    __tablename__ = "group"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id}, {self.shortname})"

    id = mapped_column(Integer, primary_key=True)
    uuid = mapped_column(String(36), unique=True, nullable=False)
    shortname = mapped_column(String(64), unique=True, nullable=False)
    fullname = mapped_column(String(256), nullable=False)

    members = relationship(
        "User",
        back_populates="belongs_to",
        cascade_backrefs=False,
    )


class Login(Base):
    __tablename__ = "login"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id})"

    id = mapped_column(Integer, primary_key=True)
    date = mapped_column(DateTime(timezone=True), nullable=False)
    # same length of User.email
    username = mapped_column(String(100))
    IP = mapped_column(String(46))
    location = mapped_column(String(256))
    user_id = mapped_column(Integer, ForeignKey("user.id"), nullable=True)
    user = relationship(
        "User",
        back_populates="logins",
        cascade_backrefs=False,
    )
    failed = mapped_column(Boolean, default=False)
    flushed = mapped_column(Boolean, default=False)
