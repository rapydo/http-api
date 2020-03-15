# -*- coding: utf-8 -*-

""" Models for the relational database """

from flask_sqlalchemy import SQLAlchemy as OriginalAlchemy

db = OriginalAlchemy()

####################################
# Define multi-multi relation
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id')),
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
    name = db.Column(db.String(255))
    surname = db.Column(db.String(255))
    email = db.Column(db.String(100), unique=True)
    authmethod = db.Column(db.String(20))
    password = db.Column(db.String(255))
    first_login = db.Column(db.DateTime)
    last_login = db.Column(db.DateTime)
    last_password_change = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    roles = db.relationship(
        'Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic')
    )


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True)
    # token = db.Column(db.String(360), unique=True)
    token = db.Column(db.Text())
    token_type = db.Column(db.String(1))
    creation = db.Column(db.DateTime)
    expiration = db.Column(db.DateTime)
    last_access = db.Column(db.DateTime)
    IP = db.Column(db.String(46))
    hostname = db.Column(db.String(256))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    emitted_for = db.relationship('User', backref=db.backref('tokens', lazy='dynamic'))
