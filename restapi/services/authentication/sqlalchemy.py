# -*- coding: utf-8 -*-

"""
Sql handling authentication process
"""

import pytz
import sqlalchemy
from datetime import datetime, timedelta
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi.utilities.htmlcodes import hcodes
from restapi.utilities.uuid import getUUID
from restapi.utilities.logs import log

if not detector.check_availability(__name__):
    log.exit("No sqlalchemy service available for authentication")


class Authentication(BaseAuthentication):

    # Also used by POST user
    def create_user(self, userdata, roles):

        if "authmethod" not in userdata:
            userdata["authmethod"] = "credentials"

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        if "uuid" not in userdata:
            userdata["uuid"] = getUUID()

        userdata = self.custom_user_properties(userdata)

        user = self.db.User(**userdata)
        self.link_roles(user, roles)

        self.db.session.add(user)

        return user

    def link_roles(self, user, roles):
        # link roles into users
        user.roles = []
        for role in roles:
            sqlrole = self.db.Role.query.filter_by(name=role).first()
            user.roles.append(sqlrole)

    def get_user_object(self, username=None, payload=None):
        user = None
        try:
            if username is not None:
                user = self.db.User.query.filter_by(email=username).first()
            if payload is not None and 'user_id' in payload:
                user = self.db.User.query.filter_by(uuid=payload['user_id']).first()
        except (sqlalchemy.exc.StatementError, sqlalchemy.exc.InvalidRequestError) as e:

            # Unable to except pymysql.err.OperationalError because:
            # ModuleNotFoundError: No module named 'pymysql.err.OperationalError';
            # 'pymysql.err' is not a package
            # Let's test exception name (OMG!)
            if type(e).__name__ == 'pymysql.err.OperationalError':
                # If you catch an error that indicates the connection was closed during
                # an operation, SQLAlchemy automatically reconnects on the next access.

                # Pessimistic approach: Add pool_pre_ping=True when creating the engine
                # The “pre ping” feature will normally emit SQL equivalent to “SELECT 1”
                # each time a connection is checked out from the pool; if an error is
                # raised that is detected as a “disconnect” situation, the connection
                # will be immediately recycled, and all other pooled connections older
                # than the current time are invalidated, so that the next time they are
                # checked out, they will also be recycled before use.
                # This add a little overhead to every connections
                # https://docs.sqlalchemy.org/en/13/core/pooling.html#pool-disconnects-pessimistic

                # Optimistic approach: try expect for connection errors.
                # When the connection attempts to use a closed connection an exception
                # is raised, then the connection calls the Pool.create() method,
                # further connections will work again by using the refreshed connection.
                # Only a single transaction will fail -> retry the operation is enough
                # https://docs.sqlalchemy.org/en/13/core/pooling.html#disconnect-handling-optimistic

                # if retry <= 0:
                #     log.error(str(e))
                #     log.warning("Errors retrieving user object, retrying...")
                #     return self.get_user_object(
                #         username=username, payload=payload, retry=1
                #     )
                raise e
            else:
                log.error(str(e))
                raise RestApiException(
                    "Backend database is unavailable",
                    status_code=hcodes.HTTP_SERVICE_UNAVAILABLE,
                )
        except (sqlalchemy.exc.DatabaseError, sqlalchemy.exc.OperationalError) as e:
            # if retry <= 0:
            #     log.error(str(e))
            #     log.warning("Errors retrieving user object, retrying...")
                # return self.get_user_object(
                #     username=username, payload=payload, retry=1)
            raise e

        return user

    def get_users(self, user_id=None):

        # Retrieve all
        if user_id is None:
            return self.db.User.query.all()

        # Retrieve one
        user = self.db.User.query.filter_by(uuid=user_id).first()
        if user is None:
            return None

        return [user]

    def get_roles(self):
        roles = []
        for role_name in self.default_roles:
            role = self.db.Role.query.filter_by(name=role_name).first()
            roles.append(role)

        return roles

    def get_roles_from_user(self, userobj=None):

        roles = []
        if userobj is None:
            try:
                userobj = self.get_user()
            except Exception as e:
                log.warning("Roles check: invalid current user.\n{}", e)
                return roles

        for role in userobj.roles:
            roles.append(role.name)
        return roles

    # TODO: (IMPORTANT) developer should be able to specify a custom init
    # which would replace this function below
    def init_users_and_roles(self):

        missing_role = missing_user = False

        try:
            # if no roles
            missing_role = not self.db.Role.query.first()
            if missing_role:
                log.warning("No roles inside db. Injected defaults.")
                for role in self.default_roles:
                    sqlrole = self.db.Role(name=role, description="automatic")
                    self.db.session.add(sqlrole)

            # if no users
            missing_user = not self.db.User.query.first()
            if missing_user:
                log.warning("No users inside db. Injected default.")
                self.create_user(
                    {
                        # 'uuid': getUUID(),
                        'email': self.default_user,
                        # 'authmethod': 'credentials',
                        'name': 'Default',
                        'surname': 'User',
                        'password': self.default_password,
                    },
                    roles=self.default_roles,
                )

            if missing_user or missing_role:
                self.db.session.commit()
        except sqlalchemy.exc.OperationalError:
            self.db.session.rollback()
            # A migration / rebuild is required?
            raise AttributeError("Inconsistences between DB schema and data models")

    def save_user(self, user):
        if user is not None:
            self.db.session.add(user)
            # try:
            self.db.session.commit()
            # except IntegrityError:
            #     self.auth.db.session.rollback()
            #     raise RestApiException("This user already exists")

    def save_token(self, user, token, jti, token_type=None):

        ip = self.get_remote_ip()
        ip_loc = self.localize_ip(ip)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now()
        exp = now + timedelta(seconds=self.shortTTL)

        token_entry = self.db.Token(
            jti=jti,
            token=token,
            token_type=token_type,
            creation=now,
            last_access=now,
            expiration=exp,
            IP=ip,
            hostname=ip_loc,
        )

        token_entry.emitted_for = user

        try:
            self.db.session.add(token_entry)
            # Save user updated in profile endpoint
            self.db.session.add(user)
            self.db.session.commit()

            log.verbose("Token stored inside the DB")
        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

    def refresh_token(self, jti):
        now = datetime.now()
        token_entry = self.db.Token.query.filter_by(jti=jti).first()
        if token_entry is None:
            return False

        if now > token_entry.expiration:
            self.invalidate_token(token=token_entry.token)
            log.info(
                "This token is no longer valid: expired since {}",
                token_entry.strftime("%d/%m/%Y")
            )
            return False

        # Verify IP validity only after grace period is expired
        if token_entry.last_access + timedelta(seconds=self.grace_period) < now:
            ip = self.get_remote_ip()
            if token_entry.IP != ip:
                log.error(
                    "This token is emitted for IP {}, invalid use from {}",
                    token_entry.IP, ip
                )
                return False

        exp = now + timedelta(seconds=self.shortTTL)

        token_entry.last_access = now
        token_entry.expiration = exp

        try:
            self.db.session.add(token_entry)
            self.db.session.commit()
        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

        return True

    def get_tokens(self, user=None, token_jti=None):
        # FIXME: TTL should be considered?

        tokens_list = []
        tokens = None

        if user is not None:
            tokens = user.tokens.all()
        elif token_jti is not None:
            tokens = [self.db.Token.query.filter_by(jti=token_jti).first()]

        if tokens is not None:
            for token in tokens:

                t = {}

                t["id"] = token.jti
                t["token"] = token.token
                t["token_type"] = token.token_type
                t["emitted"] = token.creation.strftime('%s')
                t["last_access"] = token.last_access.strftime('%s')
                if token.expiration is not None:
                    t["expiration"] = token.expiration.strftime('%s')
                t["IP"] = token.IP
                t["hostname"] = token.hostname
                tokens_list.append(t)

        return tokens_list

    def invalidate_all_tokens(self, user=None):
        """
            To invalidate all tokens the user uuid is changed
        """
        if user is None:
            user = self._user
        user.uuid = getUUID()
        try:
            self.db.session.add(user)
            self.db.session.commit()
            log.warning("User uuid changed to: {}", user.uuid)
        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()
        return True

    def invalidate_token(self, token, user=None):
        # if user is None:
        #     user = self.get_user()

        token_entry = self.db.Token.query.filter_by(token=token).first()
        if token_entry is not None:
            # Token are now deleted and no longer kept with no emision info
            # token_entry.emitted_for = None
            try:
                self.db.session.delete(token_entry)
                self.db.session.commit()
                return True
            except BaseException as e:
                log.error("Could not invalidate token ({}), rolling back", e)
                self.db.session.rollback()
                return False

        log.warning("Could not invalidate token")
        return False

    def verify_token_custom(self, jti, user, payload):
        token_entry = self.db.Token.query.filter_by(jti=jti).first()
        if token_entry is None:
            return False
        if token_entry.emitted_for is None or token_entry.emitted_for != user:
            return False

        return True

    def irods_user(self, username, session):

        user = self.get_user_object(username)

        if user is not None:
            log.debug("iRODS user already cached: {}", username)
            user.session = session
        else:

            userdata = {
                "email": username,
                "name": username,
                "surname": 'iCAT',
                "authmethod": 'irods',
                "session": session,
            }
            user = self.create_user(userdata, [self.default_role])
            try:
                self.db.session.commit()
                log.info('Cached iRODS user: {}', username)
            # except sqlalchemy.exc.IntegrityError:
            except BaseException as e:
                self.db.session.rollback()
                log.error("Errors saving iRODS user: {}", username)
                log.error(str(e))
                log.error(type(e))

                user = self.get_user_object(username)
                # Unable to do something...
                if user is None:
                    raise e
                user.session = session

        # token
        token, jti = self.create_token(self.fill_payload(user))
        now = datetime.now(pytz.utc)
        if user.first_login is None:
            user.first_login = now
        user.last_login = now
        try:
            self.db.session.add(user)
            self.db.session.commit()
        except BaseException as e:
            log.error("DB error ({}), rolling back", e)
            self.db.session.rollback()

        self.save_token(user, token, jti)

        return token, username
