# -*- coding: utf-8 -*-

"""
Mongodb based implementation
"""

from pytz import utc
from datetime import datetime, timedelta
from restapi.services.authentication import BaseAuthentication
from restapi.flask_ext.flask_mongo import AUTH_DB
from utilities.uuid import getUUID
from restapi.services.detect import detector
from utilities.logs import get_logger


log = get_logger(__name__)

if not detector.check_availability(__name__):
    log.critical_exit("No mongodb service found available currently for auth")


class Authentication(BaseAuthentication):

    def __init__(self):

        # Read init credentials and configuration
        super().__init__()

        # Get the instance for mongodb
        name = __name__.split('.')[::-1][0]  # returns 'mongo'
        from restapi.services.detect import detector
        extension = detector.services_classes.get(name)
        self.db = extension().get_instance(dbname=AUTH_DB)

    def fill_custom_payload(self, userobj, payload):
        """
        FIXME: should probably be implemented inside vanilla
        """
        return payload

    def custom_user_properties(self, userdata):
        new_userdata = super(
            Authentication, self).custom_user_properties(userdata)
        if not new_userdata.get('uuid'):
            new_userdata['uuid'] = getUUID()
        return new_userdata

    # Also used by POST user
    def create_user(self, userdata, roles):

        if "authmethod" not in userdata:
            userdata["authmethod"] = "credentials"

        if "password" in userdata:
            userdata["password"] = self.hash_password(userdata["password"])

        roles_obj = []
        for role_name in roles:
            role_obj = self.db.Role.objects.get({'_id': role_name})
            roles_obj.append(role_obj)

        userdata = self.custom_user_properties(userdata)
        userdata['roles'] = roles_obj
        user = self.db.User(**userdata)

        user.save()
        return user

    def get_user_object(self, username=None, payload=None):

        user = None

        if username is not None:
            # NOTE: email is the key, so to query use _id
            try:
                user = self.db.User.objects.raw({'_id': username}).first()
            except self.db.User.DoesNotExist:
                # don't do things, user will remain 'None'
                pass

        if payload is not None:
            if payload.get('user_id'):  # skip: '', None
                try:
                    user = self.db.User.objects.get(
                        {'uuid': payload['user_id']})
                except self.db.User.DoesNotExist:
                    pass
            elif payload.get('jti'):  # skip: '', None
                try:
                    user = self.db.Token.objects.get(
                        {'jti': payload['jti']}
                    ).user_id
                except self.db.Token.DoesNotExist:
                    pass

        return user

    def get_roles_from_user(self, userobj=None):

        roles = []
        if userobj is None:
            try:
                userobj = self.get_user()
            except Exception as e:
                log.warning("Roles check: invalid current user.\n%s", e)
                return roles

        for role in userobj.roles:
            roles.append(role.name)
            # roles.append(role)
        return roles

    def init_users_and_roles(self):

        missing_role = missing_user = False
        roles = []
        # transactions = []

        try:

            # if no roles
            cursor = self.db.Role.objects.all()
            fetch_roles = list(cursor)
            missing_role = len(fetch_roles) < 1

            if missing_role:
                log.warning("No roles inside mongo. Injected defaults.")
                for role in self.default_roles:
                    roles.append(
                        self.db.Role(
                            name=role, description="automatic").save().name
                    )
                    # if missing_role:
                    #     transactions.append(role)
                    # roles.append(role)
            else:
                # roles = fetch_roles
                for role_obj in fetch_roles:
                    roles.append(role_obj.name)

            # if no users
            cursor = self.db.User.objects.all()
            missing_user = len(list(cursor)) < 1

            if missing_user:

                self.create_user({
                    'email': self.default_user,
                    # 'authmethod': 'credentials',
                    'name': 'Default', 'surname': 'User',
                    # 'password': self.hash_password(self.default_password)
                    'password': self.default_password,
                    'last_password_change': datetime.now(utc),
                }, roles=roles)

                log.warning("No users inside mongo. Injected default one.")

        except BaseException as e:
            # raise e
            raise AttributeError("Models for auth are wrong:\n%s" % e)

        # if missing_user or missing_role:
        #     for transaction in transactions:
        #         transaction.save()
        #     log.info("Saved init transactions")

    def save_token(self, user, token, jti, token_type=None):

        ip, hostname = self.get_host_info()

        if token_type is None:
            token_type = self.FULL_TOKEN
        # FIXME: generate a token that never expires for admin tests
        now = datetime.now()
        exp = now + timedelta(seconds=self.shortTTL)

        if user is None:
            log.error("Trying to save an empty token")
        else:
            self.db.Token(
                jti=jti, token=token, token_type=token_type,
                creation=now, last_access=now, expiration=exp,
                IP=ip, hostname=hostname,
                user_id=user
            ).save()

            log.debug("Token stored inside mongo")

    def refresh_token(self, jti):

        try:
            token_entry = self.db.Token.objects.raw({'jti': jti}).first()
        except self.db.Token.DoesNotExist:
            return False

        now = datetime.now()
        if now > token_entry.expiration:
            self.invalidate_token(token=token_entry.token)
            log.critical("This token is no longer valid")
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
                tokens = self.db.Token.objects.raw(
                    {'user_id': user.email}).all()
            except self.db.Token.DoesNotExist:
                pass
        elif token_jti is not None:
            try:
                tokens.append(self.db.Token.objects.
                              raw({'jti': token_jti}).first())
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
            t["hostname"] = token.hostname
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
        log.warning("User uuid changed to: %s", user.uuid)
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

    def store_oauth2_user(self, account_type, current_user,
                          token, refresh_token):
        # FIXME: b2access
        raise NotImplementedError("to do")

    def store_proxy_cert(self, external_user, proxy):
        raise NotImplementedError("to do")

    def oauth_from_token(self, token):
        raise NotImplementedError("to do")

    def associate_object_to_attr(self, obj, key, value):
        raise NotImplementedError("to do")

    def oauth_from_local(self, internal_user):

        # log.pp(internal_user, prefix_line="internal")
        accounts = self.db.ExternalAccounts
        try:
            external_user = accounts.objects.raw(
                {'user_id': internal_user.email}).first()
        except self.db.ExternalAccounts.DoesNotExist:
            external_user = None
        return external_user
