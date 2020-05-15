# -*- coding: utf-8 -*-

"""
Implement authentication with graphdb as user database

Note: to delete the whole db
MATCH (n) OPTIONAL MATCH (n)-[r]-() DELETE n,r

Remove tokens:
MATCH (a:Token) WHERE NOT (a)<-[]-() DELETE a

"""

import pytz
from datetime import datetime, timedelta
from restapi.confs import TESTING
from restapi.services.authentication import BaseAuthentication
from restapi.services.authentication import NULL_IP
from restapi.services.detect import detector
from restapi.utilities.logs import log

if not detector.check_availability(__name__):
    log.exit("No neo4j GraphDB service found for authentication")


class Authentication(BaseAuthentication):
    def get_user_object(self, username=None, payload=None):

        if username is None and payload is None:
            return None

        user = None
        try:
            if username is not None:
                user = self.db.User.nodes.get(email=username)
            elif payload is not None and 'user_id' in payload:
                user = self.db.User.nodes.get(uuid=payload['user_id'])
        except self.db.User.DoesNotExist:
            log.warning(
                "Could not find user for username={}, payload={}", username, payload)
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

        # No user for on authenticated endpoints -> return no role
        if userobj is None:
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
        user_node.save()

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

    def init_users_and_roles(self):

        # Handle system roles
        current_roles = []
        current_roles_objs = self.db.Role.nodes.all()
        for role in current_roles_objs:
            current_roles.append(role.name)

        log.info("Current roles: {}", current_roles)

        for role_name in self.default_roles:
            if role_name not in current_roles:
                log.info("Creating role: {}", role_name)
                role_description = "automatic" if not TESTING else role_name
                role = self.db.Role(
                    name=role_name,
                    description=role_description
                )
                role.save()

        # Default user (if no users yet available)
        if not len(self.db.User.nodes) > 0:
            self.create_user(
                {
                    'email': self.default_user,
                    # 'authmethod': 'credentials',
                    'name': 'Default',
                    'surname': 'User',
                    'password': self.default_password,
                },
                roles=self.default_roles,
            )
            log.warning("Injected default user")
        else:
            log.debug("Users already created")

    def save_user(self, user):
        if user is not None:
            user.save()

    def save_token(self, user, token, payload, token_type=None):

        ip = self.get_remote_ip()
        ip_loc = self.localize_ip(ip)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now(pytz.utc)
        exp = payload.get('exp', now + timedelta(seconds=self.DEFAULT_TOKEN_TTL))

        token_node = self.db.Token()
        token_node.jti = payload['jti']
        token_node.token = token
        token_node.token_type = token_type
        token_node.creation = now
        token_node.last_access = now
        token_node.expiration = exp
        token_node.IP = ip or NULL_IP
        token_node.location = ip_loc or "Unknown"

        token_node.save()
        # Save user updated in profile endpoint
        user.save()
        token_node.emitted_for.connect(user)

    def verify_token_validity(self, jti, user):

        try:
            token_node = self.db.Token.nodes.get(jti=jti)
        except self.db.Token.DoesNotExist:
            return False

        if not token_node.emitted_for.is_connected(user):
            return False

        now = datetime.now(pytz.utc)

        if now > token_node.expiration:
            self.invalidate_token(token=token_node.token)
            log.info(
                "This token is no longer valid: expired since {}",
                token_node.expiration.strftime("%d/%m/%Y")
            )
            return False

        # Verify IP validity only after grace period is expired
        if token_node.last_access + timedelta(seconds=self.GRACE_PERIOD) < now:
            ip = self.get_remote_ip()
            if token_node.IP != ip:
                log.error(
                    "This token is emitted for IP {}, invalid use from {}",
                    token_node.IP, ip
                )
                return False

        token_node.last_access = now
        token_node.save()

        return True

    def get_tokens(self, user=None, token_jti=None, get_all=False):

        tokens_list = []
        tokens = None

        if get_all:
            tokens = self.db.Token.nodes.all()
        elif user is not None:
            tokens = user.tokens.all()
        elif token_jti is not None:
            try:
                tokens = [self.db.Token.nodes.get(jti=token_jti)]
            except self.db.Token.DoesNotExist:
                pass

        if tokens is None:
            return tokens_list

        for token in tokens:
            t = {}

            t["id"] = token.jti
            t["token"] = token.token
            t["token_type"] = token.token_type
            # t["emitted"] = token.creation.strftime('%s')
            # t["last_access"] = token.last_access.strftime('%s')
            # if token.expiration is not None:
            #     t["expiration"] = token.expiration.strftime('%s')
            t["emitted"] = token.creation
            t["last_access"] = token.last_access
            t["expiration"] = token.expiration
            t["IP"] = token.IP
            t["location"] = token.location
            if get_all:
                t['user'] = self.db.getSingleLinkedNode(token.emitted_for)

            tokens_list.append(t)

        return tokens_list

    def invalidate_token(self, token):
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
