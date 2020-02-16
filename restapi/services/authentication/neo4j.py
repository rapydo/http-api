# -*- coding: utf-8 -*-

"""
Implement authentication with graphdb as user database

Note: to delete the whole db
MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r

Remove tokens:
MATCH (a:Token) WHERE NOT (a)<-[]-() DELETE a

"""

from datetime import datetime, timedelta
import pytz
from restapi.utilities.uuid import getUUID
from restapi.services.authentication import BaseAuthentication
from restapi.services.detect import detector
from restapi.utilities.logs import log

if not detector.check_availability(__name__):
    log.exit("No neo4j GraphDB service found for authentication")


class Authentication(BaseAuthentication):
    def get_user_object(self, username=None, payload=None):

        from neomodel.exceptions import DeflateError
        from neo4j.exceptions import ServiceUnavailable

        user = None
        try:
            if username is not None:
                user = self.db.User.nodes.get(email=username)
            if payload is not None and 'user_id' in payload:
                user = self.db.User.nodes.get(uuid=payload['user_id'])
        except ServiceUnavailable as e:
            self.db.refresh_connection()
            raise e
        except DeflateError:
            log.warning("Invalid username '{}'", username)
        except self.db.User.DoesNotExist:
            log.warning("Could not find user for '{}'", username)
        return user

    def get_users(self, user_id=None):

        # Retrieve all
        if user_id is None:
            return self.db.User.nodes.all()

        # Retrieve one
        user = self.db.User.nodes.get_or_none(uuid=user_id)
        if user is None:
            return None

        return [user]

    def get_roles(self):
        roles = []
        for role in self.db.Role.nodes.all():
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

        for role in userobj.roles.all():
            roles.append(role.name)
        return roles

    # Also used by POST user
    def create_user(self, userdata, roles):

        if "authmethod" not in userdata:
            userdata["authmethod"] = "credentials"

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata = self.custom_user_properties(userdata)

        user_node = self.db.User(**userdata)
        try:
            user_node.save()
        except Exception as e:
            message = "Can't create user {}:\n{}".format(userdata['email'], e)
            log.error(message)
            raise AttributeError(message)

        self.link_roles(user_node, roles)

        return user_node

    # Also used by PUT user
    def link_roles(self, user, roles):

        for p in user.roles.all():
            user.roles.disconnect(p)

        for role in roles:
            log.debug("Adding role {}", role)
            try:
                role_obj = self.db.Role.nodes.get(name=role)
            except self.db.Role.DoesNotExist:
                raise Exception("Graph role {} does not exist".format(role))
            user.roles.connect(role_obj)

    def create_role(self, role, description="automatic"):
        role = self.db.Role(name=role, description=description)
        role.save()
        return role

    def init_users_and_roles(self):

        # Handle system roles
        current_roles = []
        current_roles_objs = self.db.Role.nodes.all()
        for role in current_roles_objs:
            current_roles.append(role.name)

        log.info("Current roles: {}", current_roles)

        for role in self.default_roles:
            if role not in current_roles:
                log.info("Creating role: {}", role)
                self.create_role(role)

        # Default user (if no users yet available)
        if not len(self.db.User.nodes) > 0:
            log.warning("No users inside graphdb. Injecting default.")
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
        else:
            log.debug("Users already created")

    def save_user(self, user):
        if user is not None:
            user.save()

    def save_token(self, user, token, jti, token_type=None):

        ip = self.get_remote_ip()
        ip_loc = self.localize_ip(ip)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now(pytz.utc)
        exp = now + timedelta(seconds=self.shortTTL)

        token_node = self.db.Token()
        token_node.jti = jti
        token_node.token = token
        token_node.token_type = token_type
        token_node.creation = now
        token_node.last_access = now
        token_node.expiration = exp
        token_node.IP = ip
        token_node.hostname = ip_loc

        token_node.save()
        # Save user updated in profile endpoint
        user.save()
        token_node.emitted_for.connect(user)

    def verify_token_custom(self, jti, user, payload):
        try:
            token_node = self.db.Token.nodes.get(jti=jti)
        except self.db.Token.DoesNotExist:
            return False
        if not token_node.emitted_for.is_connected(user):
            return False

        return True

    def refresh_token(self, jti):
        now = datetime.now(pytz.utc)
        try:
            token_node = self.db.Token.nodes.get(jti=jti)

            if now > token_node.expiration:
                self.invalidate_token(token=token_node.token)
                log.info(
                    "This token is no longer valid: expired since {}",
                    token_node.expiration.strftime("%d/%m/%Y")
                )
                return False

            # Verify IP validity only after grace period is expired
            if token_node.last_access + timedelta(seconds=self.grace_period) < now:
                ip = self.get_remote_ip()
                if token_node.IP != ip:
                    log.error(
                        "This token is emitted for IP {}, invalid use from {}",
                        token_node.IP, ip
                    )
                    return False

            exp = now + timedelta(seconds=self.shortTTL)

            token_node.last_access = now
            token_node.expiration = exp

            token_node.save()

            return True
        except self.db.Token.DoesNotExist:
            log.warning("Token {} not found", jti)
            return False

    def get_tokens(self, user=None, token_jti=None):
        # FIXME: TTL should be considered?

        tokens_list = []
        tokens = None

        if user is not None:
            tokens = user.tokens.all()
        elif token_jti is not None:
            try:
                tokens = [self.db.Token.nodes.get(jti=token_jti)]
            except self.db.Token.DoesNotExist:
                pass

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
        if user is None:
            user = self.get_user()

        user.uuid = getUUID()
        user.save()
        return True

    def invalidate_token(self, token, user=None):
        # if user is None:
        #     user = self.get_user()
        try:
            token_node = self.db.Token.nodes.get(token=token)
            token_node.delete()
        except self.db.Token.DoesNotExist:
            log.warning("Unable to invalidate, token not found: {}", token)
            return False
        return True

    # def clean_pending_tokens(self):
    #     log.debug("Removing all pending tokens")
    #     return self.cypher("MATCH (a:Token) WHERE NOT (a)<-[]-() DELETE a")
