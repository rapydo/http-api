# -*- coding: utf-8 -*-

"""
Mongodb based implementation
"""

from datetime import datetime, timedelta
from rapydo.services.authentication import BaseAuthentication
from rapydo.utils.uuid import getUUID
from rapydo.services.detect import detector
from rapydo.utils.logs import get_logger


log = get_logger(__name__)

if not detector.check_availability(__name__):
    log.critical_exit("No mongodb service found available currently for auth")


class Authentication(BaseAuthentication):

    # def __init__(self, services=None):
    #     # Read init credentials and configuration
    #     self.myinit()
    #     # Get the instance for mongodb
    #     name = __name__.split('.')[::-1][0]  # returns 'mongo'
    #     self.db = services.get(name).get_instance(dbname='auth')

    # TOFIX: how to call a specific instance with a specific db

    def fill_custom_payload(self, userobj, payload):
        """
        TOFIX: should probably be implemented inside vanilla
        """
        return payload

    def get_user_object(self, username=None, payload=None):

        user = None

        if username is not None:
            # NOTE: email is the key, so to query use _id
            try:
                user = self.db.User.objects.raw({'_id': username}).first()
            except self.db.User.DoesNotExist:
                # don't do things, user will remain 'None'
                pass

        if payload is not None and 'user_id' in payload:
            try:
                user = self.db.User.objects.raw(
                    {'uuid': payload['user_id']}).first()
            except self.db.User.DoesNotExist:
                pass

        return user

    def get_roles_from_user(self, userobj=None):

        roles = []
        if userobj is None:
            try:
                userobj = self.get_user()
            except Exception as e:
                log.warning("Roles check: invalid current user.\n%s" % e)
                return roles

        for role in userobj.roles:
            roles.append(role.name)
        return roles

    def init_users_and_roles(self):

        missing_role = missing_user = False
        roles = []
        transactions = []

        try:

            # if no roles
            cursor = self.db.Role.objects.all()
            missing_role = len(list(cursor)) < 1

            for role in self.default_roles:
                role = self.db.Role(name=role, description="automatic")
                if missing_role:
                    transactions.append(role)
                roles.append(role)

            if missing_role:
                log.warning("No roles inside mongo. Injected defaults.")

            # if no users
            cursor = self.db.User.objects.all()
            missing_user = len(list(cursor)) < 1

            if missing_user:
                user = self.db.User(
                    uuid=getUUID(),
                    email=self.default_user,
                    authmethod='credentials',
                    name='Default', surname='User',
                    password=self.hash_password(self.default_password))

                # link roles into users
                user.roles = roles
                # for role in roles:
                #     user.roles.append(role)

                transactions.append(user)
                log.warning("No users inside mongo. Injected default.")

        except BaseException as e:
            raise AttributeError("Models for auth are wrong:\n%s" % e)

        if missing_user or missing_role:
            for transaction in transactions:
                transaction.save()
            log.info("Saved init transactions")

    def save_token(self, user, token, jti):

        from flask import request
        import socket
        ip = request.remote_addr
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        except Exception:
            hostname = ""

        # TOFIX: generate a token that never expires for admin tests
        now = datetime.now()
        exp = now + timedelta(seconds=self.shortTTL)

        if user is None:
            log.error("Trying to save an empty token")
        else:
            self.db.Token(
                jti=jti, token=token,
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
        log.warning("User uuid changed to: %s" % user.uuid)
        return True

    def invalidate_token(self, token, user=None):
        if user is None:
            user = self.get_user()

        try:
            token_entry = self.db.Token.objects.raw({'token': token}).first()
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

    def store_oauth2_user(self, current_user, token):
        # FIXME: b2access
        raise NotImplementedError("to do")
#         """
#         Allow external accounts (oauth2 credentials)
#         to be connected to internal local user
#         """

#         try:
#             values = current_user.data
#         except:
#             return None, "Authorized response is invalid"

#         # print("TEST", values, type(values))
#         if not isinstance(values, dict) or len(values) < 1:
#             return None, "Authorized response is empty"

#         email = values.get('email')
#         cn = values.get('cn')
#         ui = values.get('unity:persistent')

#         # DN very strange: the current key is something like 'urn:oid:2.5.4.49'
#         # is it going to change?
#         dn = None
#         for key, value in values.items():
#             if 'urn:oid' in key:
#                 dn = values.get(key)
#         if dn is None:
#             return None, "Missing DN from authorized response..."

#         # Check if a user already exists with this email
#         internal_user = None
#         internal_users = self.db.User.query.filter(
#             self.db.User.email == email).all()

#         # If something found
#         if len(internal_users) > 0:
#             # Should never happen, please
#             if len(internal_users) > 1:
#                 log.critical("Multiple users?")
#                 return None, "Server misconfiguration"
#             internal_user = internal_users.pop()
#             log.debug("Existing internal user: %s" % internal_user)
#             # A user already locally exists with another authmethod. Not good.
#             if internal_user.authmethod != 'oauth2':
#                 return None, "Creating a user which locally already exists"
#         # If missing, add it locally
#         else:
#             # Create new one
#             internal_user = self.db.User(
#                 uuid=getUUID(), email=email, authmethod='oauth2')
#             # link default role into users
#             internal_user.roles.append(
#                 self.db.Role.query.filter_by(name=self.default_role).first())
#             self.db.session.add(internal_user)
#             self.db.session.commit()
#             log.info("Created internal user %s" % internal_user)

#         # Get ExternalAccount for the oauth2 data if exists
#         external_user = self.db.ExternalAccounts \
#             .query.filter_by(username=email).first()
#         # or create it otherwise
#         if external_user is None:
#             external_user = self.db.ExternalAccounts(username=email, unity=ui)

#             # Connect the external account to the current user
#             external_user.main_user = internal_user
#             # Note: for pre-production release
#             # we allow only one external account per local user
#             log.info("Created external user %s" % external_user)

#         # Update external user data to latest info received
#         external_user.email = email
#         external_user.token = token
#         external_user.certificate_cn = cn
#         external_user.certificate_dn = dn

#         self.db.session.add(external_user)
#         self.db.session.commit()
#         log.debug("Updated external user %s" % external_user)

#         return internal_user, external_user

    def store_proxy_cert(self, external_user, proxy):
        raise NotImplementedError("to do")
#         if external_user is None:
#             return False
#         external_user.proxyfile = proxy
#         self.db.session.add(external_user)  # can be commented
#         self.db.session.commit()
#         return True

    def oauth_from_token(self, token):
        raise NotImplementedError("to do")
#         extus = self.db.ExternalAccounts.query.filter_by(token=token).first()
#         intus = extus.main_user
#         # print(token, intus, extus)
#         return intus, extus

    def associate_object_to_attr(self, obj, key, value):
        raise NotImplementedError("to do")

#         setattr(obj, key, value)
#         self.db.session.commit()
#         return

    def oauth_from_local(self, internal_user):

        log.pp(internal_user, prefix_line="internal")
        accounts = self.db.ExternalAccounts
        try:
            external_user = accounts.objects.raw(
                {'user_id': internal_user.email}).first()
        except self.db.ExternalAccounts.DoesNotExist:
            external_user = None
        return internal_user, external_user
