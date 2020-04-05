# -*- coding: utf-8 -*-

"""
Mongodb based implementation
"""

from pytz import utc
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
from restapi.services.authentication import BaseAuthentication
from restapi.connectors.mongo import AUTH_DB
from restapi.utilities.uuid import getUUID
from restapi.services.detect import detector
from restapi.utilities.logs import log


if not detector.check_availability(__name__):
    log.exit("No mongodb service available for authentication")


class Authentication(BaseAuthentication):
    def __init__(self):

        # Read init credentials and configuration
        super().__init__()

        # Get the instance for mongodb
        name = __name__.split('.')[::-1][0]  # returns 'mongo'

        Connector = detector.services_classes.get(name)
        self.db = Connector().get_instance(dbname=AUTH_DB)

    def custom_user_properties(self, userdata):
        new_userdata = super(Authentication, self).custom_user_properties(userdata)
        if not new_userdata.get('uuid'):
            new_userdata['uuid'] = getUUID()
        if not new_userdata.get('id'):
            new_userdata['id'] = new_userdata['uuid']
        return new_userdata

    # Also used by POST user
    def create_user(self, userdata, roles):

        try:
            if "authmethod" not in userdata:
                userdata["authmethod"] = "credentials"

            if "password" in userdata:
                userdata["password"] = self.get_password_hash(userdata["password"])

            userdata = self.custom_user_properties(userdata)
            user = self.db.User(**userdata)

            self.link_roles(user, roles)

            user.save()
            return user
        except DuplicateKeyError as e:
            message = "Can't create user {}\n{}".format(userdata['email'], e)
            log.error(message)
            raise AttributeError(message)

    def link_roles(self, user, roles):

        roles_obj = []
        for role_name in roles:
            role_obj = self.db.Role.objects.get({'name': role_name})
            roles_obj.append(role_obj)
        user.roles = roles_obj

    def get_user_object(self, username=None, payload=None):

        user = None

        if username is not None:
            # NOTE: email is the key, so to query use _id
            try:
                user = self.db.User.objects.raw({'email': username}).first()
            except self.db.User.DoesNotExist:
                # don't do things, user will remain 'None'
                pass

        if payload is not None:
            if payload.get('user_id'):  # skip: '', None
                try:
                    user = self.db.User.objects.get({'uuid': payload['user_id']})
                except self.db.User.DoesNotExist:
                    pass
            elif payload.get('jti'):  # skip: '', None
                try:
                    user = self.db.Token.objects.get({'jti': payload['jti']}).user_id
                except self.db.Token.DoesNotExist:
                    pass

        return user

    def get_users(self, user_id=None):

        # Retrieve all
        if user_id is None:
            return self.db.User.objects.all()

        # Retrieve one
        try:
            user = self.db.User.objects.get({'uuid': user_id})
        except self.db.User.DoesNotExist:
            return None

        if user is None:
            return None

        return [user]

    def get_roles(self):
        roles = []
        for role_name in self.default_roles:
            try:
                role = self.db.Role.objects.get({'name': role_name})
                roles.append(role)
            except self.db.Role.DoesNotExist:
                log.warning("Role not found: {}", role_name)

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
            # roles.append(role)
        return roles

    def init_users_and_roles(self):

        roles = []

        for role_name in self.default_roles:
            try:
                role = self.db.Role.objects.get({'name': role_name})
                roles.append(role.name)
                log.info("Role already exists: {}", role.name)
            except self.db.Role.DoesNotExist:
                role = self.db.Role(name=role_name, description="automatic")
                role.save()
                roles.append(role.name)
                log.warning("Injected default role: {}", role.name)

        try:

            # if no users
            cursor = self.db.User.objects.all()
            if len(list(cursor)) > 0:
                log.info("No user injected")
            else:

                self.create_user(
                    {
                        'email': self.default_user,
                        'name': 'Default',
                        'surname': 'User',
                        'password': self.default_password,
                        'last_password_change': datetime.now(utc),
                    },
                    roles=roles,
                )

                log.warning("Injected default user")

        except BaseException as e:
            raise AttributeError("Models for auth are wrong:\n{}".format(e))

    def save_user(self, user):
        if user is not None:
            user.save()

    def save_token(self, user, token, jti, token_type=None):

        ip = self.get_remote_ip()
        ip_loc = self.localize_ip(ip)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now()
        exp = now + timedelta(seconds=self.shortTTL)

        if user is None:
            log.error("Trying to save an empty token")
        else:
            self.db.Token(
                jti=jti,
                token=token,
                token_type=token_type,
                creation=now,
                last_access=now,
                expiration=exp,
                IP=ip,
                location=ip_loc,
                user_id=user,
            ).save()

            # Save user updated in profile endpoint
            user.save()

    def refresh_token(self, jti):

        try:
            token_entry = self.db.Token.objects.raw({'jti': jti}).first()
        except self.db.Token.DoesNotExist:
            return False

        now = datetime.now()
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

        token_entry.save()
        return True

    def get_tokens(self, user=None, token_jti=None):

        returning_tokens = []
        tokens = []

        if user is not None:
            try:
                tokens = self.db.Token.objects.raw({'user_id': user.id}).all()
            except self.db.Token.DoesNotExist:
                pass
        elif token_jti is not None:
            try:
                tokens.append(self.db.Token.objects.raw({'jti': token_jti}).first())
            except self.db.Token.DoesNotExist:
                pass

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
            t["location"] = token.location
            returning_tokens.append(t)

        return returning_tokens

    def invalidate_all_tokens(self, user=None):
        """
            To invalidate all tokens the user uuid is changed
        """
        if user is None:
            user = self._user
        user.uuid = getUUID()
        user.save()
        log.warning("User uuid changed to: {}", user.uuid)
        return True

    def invalidate_token(self, token, user=None):
        if user is None:
            user = self.get_user()

        try:
            token_entry = self.db.Token.objects.raw({'token': token}).first()
            # NOTE: Other auth db (sqlalchemy, neo4j) delete the token instead
            # of keep it without the user association
            token_entry.user_id = None
            token_entry.save()
        except self.db.Token.DoesNotExist:
            log.warning("Could not invalidate non-existing token")

        return True

    def verify_token_custom(self, jti, user, payload):

        try:
            token = self.db.Token.objects.raw({'jti': jti}).first()
        except self.db.Token.DoesNotExist:
            return False

        if token.user_id is None or token.user_id.email != user.email:
            return False

        return True
