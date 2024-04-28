""" Models for the relational database """

from datetime import datetime
from typing import Optional

from sqlalchemy import Column, DateTime, ForeignKey, String, Table
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# Define multi-multi relation
roles_users = Table(
    "roles_users",
    Base.metadata,
    Column("user_id", ForeignKey("user.id")),
    Column("role_id", ForeignKey("role.id")),
)


class Role(Base):
    __tablename__ = "role"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id}, {self.name})"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=False)

    users: Mapped[list["User"]] = relationship(
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

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255, collation=None), nullable=False)
    surname: Mapped[str] = mapped_column(String(255, collation=None), nullable=False)
    authmethod: Mapped[str] = mapped_column(String(20), nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    mfa_hash: Mapped[Optional[str]] = mapped_column(String(255))
    first_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_password_change: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True)
    )
    is_active: Mapped[bool] = mapped_column(default=True)
    privacy_accepted: Mapped[bool] = mapped_column(default=True)
    expiration: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    roles: Mapped[list["Role"]] = relationship(
        "Role",
        secondary=roles_users,
        back_populates="users",
    )
    group_id: Mapped[int] = mapped_column(ForeignKey("group.id"))
    belongs_to: Mapped["Group"] = relationship(
        "Group",
        back_populates="members",
        cascade_backrefs=False,
        foreign_keys=[group_id],
    )
    tokens: Mapped[list["Token"]] = relationship(
        "Token",
        back_populates="emitted_for",
        cascade_backrefs=False,
        cascade="delete",
    )
    logins: Mapped[list["Login"]] = relationship(
        "Login",
        back_populates="user",
        cascade_backrefs=False,
        cascade="delete",
    )


class Token(Base):
    __tablename__ = "token"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id})"

    id: Mapped[int] = mapped_column(primary_key=True)
    jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    token: Mapped[str] = mapped_column(nullable=False)
    token_type: Mapped[str] = mapped_column(String(1), nullable=False)
    creation: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expiration: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_access: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    IP: Mapped[Optional[str]] = mapped_column(String(46))
    location: Mapped[Optional[str]] = mapped_column(String(256))
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    emitted_for: Mapped["User"] = relationship(
        "User",
        back_populates="tokens",
        cascade_backrefs=False,
    )


class Group(Base):
    __tablename__ = "group"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id}, {self.shortname})"

    id: Mapped[int] = mapped_column(primary_key=True)
    uuid: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    shortname: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    fullname: Mapped[str] = mapped_column(String(256), nullable=False)

    members: Mapped[list["User"]] = relationship(
        "User",
        back_populates="belongs_to",
        cascade_backrefs=False,
    )


class Login(Base):
    __tablename__ = "login"

    def __repr__(self) -> str:  # pragma: no cover
        name = self.__class__.__name__
        return f"{name}({self.id})"

    id: Mapped[int] = mapped_column(primary_key=True)
    date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    username: Mapped[Optional[str]] = mapped_column(String(100))
    IP: Mapped[Optional[str]] = mapped_column(String(46))
    location: Mapped[Optional[str]] = mapped_column(String(256))
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=True)
    user: Mapped["User"] = relationship(
        "User",
        back_populates="logins",
        cascade_backrefs=False,
    )
    failed: Mapped[bool] = mapped_column(default=False)
    flushed: Mapped[bool] = mapped_column(default=False)
