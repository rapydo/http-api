""" Neo4j GraphDB flask connector """

import re
import socket
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Union, cast

import pytz
from neo4j.exceptions import AuthError, CypherSyntaxError, ServiceUnavailable
from neobolt.addressing import AddressError as neobolt_AddressError
from neobolt.exceptions import ServiceUnavailable as neobolt_ServiceUnavailable
from neomodel import (  # install_all_labels,
    StructuredNode,
    clear_neo4j_database,
    config,
    db,
    install_labels,
    remove_all_labels,
)
from neomodel.exceptions import (
    DeflateError,
    DoesNotExist,
    RequiredProperty,
    UniqueProperty,
)
from neomodel.match import NodeSet

from restapi.connectors import Connector
from restapi.exceptions import BadRequest, DatabaseDuplicatedEntry, RestApiException
from restapi.services.authentication import (
    BaseAuthentication,
    Group,
    Payload,
    RoleObj,
    Token,
    User,
)
from restapi.utilities.logs import Events, log


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)
        except DatabaseDuplicatedEntry as e:
            # already catched and parser, raise up
            raise (e)
        except DoesNotExist as e:
            raise (e)
        except CypherSyntaxError as e:
            raise (e)
        except UniqueProperty as e:

            t = "already exists with label"
            m = re.search(
                fr"Node\([0-9]+\) {t} `(.+)` and property `(.+)` = '(.+)'", str(e)
            )

            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = f"A {node.title()} already exists with {prop}: {val}"
                raise DatabaseDuplicatedEntry(error)

            # Can't be tested, should never happen except in case of new neo4j version
            log.error("Unrecognized error message: {}", e)  # pragma: no cover
            raise DatabaseDuplicatedEntry("Duplicated entry")  # pragma: no cover
        except RequiredProperty as e:

            # message = property 'xyz' on objects of class XYZ

            message = str(e)
            m = re.search(r"property '(.*)' on objects of class (.*)", str(e))
            if m:
                missing_property = m.group(1)
                model = m.group(2)
                message = f"Missing property {missing_property} required by {model}"

            raise BadRequest(message)
        except DeflateError as e:
            log.warning(e)
            return None

        except ServiceUnavailable:  # pragma: no cover
            # refresh_connection()
            raise

        # Catched in case of re-raise for example RequiredProperty -> BadRequest
        except RestApiException:  # pragma: no cover
            raise

        except Exception as e:  # pragma: no cover
            log.critical("Raised unknown exception: {}", type(e))
            raise e

    return wrapper


class NeoModel(Connector):

    # This is used to return Models in a type-safe way
    def __getattr__(self, name: str) -> StructuredNode:
        if name in self._models:
            return self._models[name]
        raise AttributeError(f"Model {name} not found")

    def get_connection_exception(self):

        return (
            neobolt_ServiceUnavailable,
            neobolt_AddressError,
            AuthError,
            socket.gaierror,
            # REALLY?? A ValueError!? :-(
            # Raised here:
            # https://github.com/neo4j/neo4j-python-driver/blob/d36334e80a66d57b32621d319032751d2204ef67/neo4j/addressing.py#L112
            ValueError,
        )

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        USER = variables.get("user", "neo4j")
        PWD = variables.get("password")
        HOST = variables.get("host")
        PORT = variables.get("port")
        URI = f"bolt://{USER}:{PWD}@{HOST}:{PORT}"
        config.DATABASE_URL = URI
        # Ensure all DateTimes are provided with a timezone
        # before being serialised to UTC epoch
        config.FORCE_TIMEZONE = True  # default False
        db.url = URI
        db.set_connection(URI)

        StructuredNode.save = catch_db_exceptions(StructuredNode.save)
        NodeSet.get = catch_db_exceptions(NodeSet.get)

        self.db = db
        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:
        log.warning("neo4j.is_connected method is not implemented")
        return not self.disconnected

    def initialize(self) -> None:

        if self.app:
            with self.app.app_context():
                remove_all_labels()
                # install_all_labels()

                # install_all_labels can fail when models are cross-referenced between
                # core and custom. For example:
                # neo4j.exceptions.ClientError:
                #     {code: Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists}
                #     {message: An equivalent constraint already exists,
                #         'Constraint( type='UNIQUENESS', schema=(:XYZ {uuid}), [...]
                # This loop with install_labels prevent errors
                for model in self._models.values():
                    install_labels(model, quiet=False)

    def destroy(self) -> None:

        graph = self.get_instance()

        if self.app:
            with self.app.app_context():
                log.critical("Destroy current Neo4j data")

                clear_neo4j_database(graph.db)

    # def refresh_connection(self):
    #     if self.db.url is None:
    #         log.critical("Unable to refresh neo4j connection")
    #         return False

    #     log.info("Refreshing neo4j connection...")
    #     self.db.set_connection(self.db.url)
    #     return True

    @staticmethod
    def update_properties(instance, properties):

        for field, value in properties.items():
            instance.__dict__[field] = value

    @catch_db_exceptions
    def cypher(self, query):
        """ Execute normal neo4j queries """
        try:
            # results, meta = db.cypher_query(query)
            results, _ = db.cypher_query(query)
        except CypherSyntaxError as e:
            log.warning(query)
            log.error(f"Failed to execute Cypher Query\n{e}")
            raise CypherSyntaxError("Failed to execute Cypher Query")
        return results

    @staticmethod
    def sanitize_input(term):
        """
        Strip and clean up term from special characters.
        """
        return term.strip().replace("*", "").replace("'", "\\'").replace("~", "")

    @staticmethod
    def fuzzy_tokenize(term):
        tokens = re.findall(r'[^"\s]\S*|".+?"', term)
        for index, t in enumerate(tokens):

            # Do not apply fuzzy search to quoted strings
            if '"' in t:
                continue

            # Do not apply fuzzy search to special characters
            if t == "+" or t == "!":
                continue

            # Do not apply fuzzy search to special operators
            if t == "AND" or t == "OR" or t == "NOT":
                continue

            tokens[index] += "~1"

        return " ".join(tokens)


class Authentication(BaseAuthentication):
    def __init__(self):
        self.db = get_instance()

    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:

        if username:
            return self.db.User.nodes.get_or_none(email=username)

        if user_id:
            return self.db.User.nodes.get_or_none(uuid=user_id)

        # reached if both username and user_id are None
        return None

    def get_users(self) -> List[User]:
        return cast(List[User], self.db.User.nodes.all())

    def save_user(self, user: User) -> bool:
        if not user:
            return False

        user.save()
        return True

    def delete_user(self, user: User) -> bool:
        if not user:
            return False

        user.delete()
        return True

    def get_group(
        self, group_id: Optional[str] = None, name: Optional[str] = None
    ) -> Optional[Group]:
        if group_id:
            return self.db.Group.nodes.get_or_none(uuid=group_id)

        if name:
            return self.db.Group.nodes.get_or_none(shortname=name)

        return None

    def get_groups(self) -> List[Group]:
        return cast(List[Group], self.db.Group.nodes.all())

    def save_group(self, group: Group) -> bool:
        if not group:
            return False

        group.save()
        return True

    def delete_group(self, group: Group) -> bool:
        if not group:
            return False

        group.delete()
        return True

    def get_roles(self) -> List[RoleObj]:
        roles = []
        for role in self.db.Role.nodes.all():
            if role:
                roles.append(role)

        return roles

    def get_roles_from_user(self, user: Optional[User]) -> List[str]:

        # No user for non authenticated endpoints -> return no role
        if user is None:
            return []

        return [role.name for role in user.roles.all()]

    def create_role(self, name: str, description: str) -> None:
        role = self.db.Role(name=name, description=description)
        role.save()

    def save_role(self, role: RoleObj) -> bool:
        if role:
            role.save()
            return True
        return False

    # Also used by POST user
    def create_user(self, userdata: Dict[str, Any], roles: List[str]) -> User:

        userdata.setdefault("authmethod", "credentials")

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata, extra_userdata = self.custom_user_properties_pre(userdata)

        user = self.db.User(**userdata)
        user.save()

        self.link_roles(user, roles)

        self.custom_user_properties_post(user, userdata, extra_userdata, self.db)

        return user

    # Also used by PUT user
    def link_roles(self, user: User, roles: List[str]) -> None:

        if not roles:
            roles = [self.default_role]

        for p in user.roles.all():
            user.roles.disconnect(p)

        for role in roles:
            log.debug("Adding role {}", role)
            try:
                role_obj = self.db.Role.nodes.get(name=role)
            except self.db.Role.DoesNotExist:  # pragma: no cover
                raise Exception(f"Graph role {role} does not exist")
            user.roles.connect(role_obj)

    def create_group(self, groupdata: Dict[str, Any]) -> Group:
        group = self.db.Group(**groupdata).save()

        return group

    def add_user_to_group(self, user: User, group: Group) -> None:

        if user and group:
            prev_group = user.belongs_to.single()

            if prev_group is not None:
                user.belongs_to.reconnect(prev_group, group)
            elif prev_group == group:
                pass
            else:
                user.belongs_to.connect(group)

    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:

        ip_address = self.get_remote_ip()
        ip_loc = self.localize_ip(ip_address)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now(pytz.utc)
        exp = payload.get("exp", now + timedelta(seconds=self.DEFAULT_TOKEN_TTL))

        token_node = self.db.Token()
        token_node.jti = payload["jti"]
        token_node.token = token
        token_node.token_type = token_type
        token_node.creation = now
        token_node.last_access = now
        token_node.expiration = exp
        token_node.IP = ip_address
        token_node.location = ip_loc or "Unknown"

        token_node.save()
        # Save user updated in profile endpoint
        user.save()
        token_node.emitted_for.connect(user)

    def verify_token_validity(self, jti: str, user: User) -> bool:

        try:
            token_node = self.db.Token.nodes.get(jti=jti)
        except self.db.Token.DoesNotExist:
            return False

        if not token_node.emitted_for.is_connected(user):  # pragma: no cover
            return False

        now = datetime.now(pytz.utc)

        if now > token_node.expiration:
            self.invalidate_token(token=token_node.token)
            log.info(
                "This token is no longer valid: expired since {}",
                token_node.expiration.strftime("%d/%m/%Y"),
            )
            return False

        # Verify IP validity only after grace period is expired
        if token_node.creation + self.GRACE_PERIOD < now:
            ip = self.get_remote_ip()
            if token_node.IP != ip:
                log.error(
                    "This token is emitted for IP {}, invalid use from {}",
                    token_node.IP,
                    ip,
                )
                return False

        if token_node.last_access + self.SAVE_LAST_ACCESS_EVERY < now:
            token_node.last_access = now
            token_node.save()

        return True

    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:

        tokens_list: List[Token] = []
        tokens = None

        if get_all:
            tokens = self.db.Token.nodes.all()
        elif user:
            tokens = user.tokens.all()
        elif token_jti:
            try:
                tokens = [self.db.Token.nodes.get(jti=token_jti)]
            except self.db.Token.DoesNotExist:
                pass

        if tokens:
            for token in tokens:
                t: Token = {
                    "id": token.jti,
                    "token": token.token,
                    "token_type": token.token_type,
                    "emitted": token.creation,
                    "last_access": token.last_access,
                    "expiration": token.expiration,
                    "IP": token.IP,
                    "location": token.location,
                }
                if get_all:
                    t["user"] = token.emitted_for.single()

                tokens_list.append(t)

        return tokens_list

    def invalidate_token(self, token: str) -> bool:
        try:
            token_node = self.db.Token.nodes.get(token=token)
            token_node.delete()
            self.log_event(Events.delete, target=token_node)
        except self.db.Token.DoesNotExist:
            log.warning("Unable to invalidate, token not found: {}", token)
            return False
        return True


instance = NeoModel()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "NeoModel":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
