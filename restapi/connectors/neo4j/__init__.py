""" Neo4j GraphDB flask connector """

import re
import socket
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

import pytz
from neo4j.exceptions import AuthError, CypherSyntaxError, ServiceUnavailable
from neobolt.addressing import AddressError as neobolt_AddressError
from neobolt.exceptions import ServiceUnavailable as neobolt_ServiceUnavailable
from neomodel import (
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

from restapi.connectors import Connector, ExceptionsList
from restapi.exceptions import (
    DatabaseDuplicatedEntry,
    DatabaseMissingRequiredProperty,
    RestApiException,
)
from restapi.services.authentication import (
    BaseAuthentication,
    Group,
    Login,
    Payload,
    RoleObj,
    Token,
    User,
)
from restapi.utilities.logs import Events, log

F = TypeVar("F", bound=Callable[..., Any])


def catch_db_exceptions(func: F) -> F:
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:

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

            raise DatabaseMissingRequiredProperty(message)
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

    return cast(F, wrapper)


class NeoModel(Connector):

    # This is used to return Models in a type-safe way
    # Return type becomes "Any" due to an unfollowed import
    def __getattr__(self, name: str) -> StructuredNode:  # type: ignore
        if name in self._models:
            return self._models[name]
        raise AttributeError(f"Model {name} not found")

    @staticmethod
    def get_connection_exception() -> ExceptionsList:

        return (
            neobolt_ServiceUnavailable,
            neobolt_AddressError,
            ServiceUnavailable,
            AuthError,
            socket.gaierror,
            # REALLY?? A ValueError!? :-(
            # Raised here:
            # https://github.com/neo4j/neo4j-python-driver/blob/d36334e80a66d57b32621d319032751d2204ef67/neo4j/addressing.py#L112
            ValueError,
        )  # type: ignore

    def connect(self, **kwargs: str) -> "NeoModel":

        variables = self.variables.copy()
        variables.update(kwargs)

        USER = variables.get("user", "neo4j")
        PWD = variables.get("password")
        HOST = variables.get("host")
        PORT = variables.get("port")
        # Fixed... to be configured?
        DATABASE = "neo4j"
        URI = f"bolt://{USER}:{PWD}@{HOST}:{PORT}/{DATABASE}"
        config.DATABASE_URL = URI
        # Ensure all DateTimes are provided with a timezone
        # before being serialised to UTC epoch
        config.FORCE_TIMEZONE = True  # default False
        db.url = URI
        db.set_connection(URI)

        # db.driver.verify_connectivity()

        StructuredNode.save = catch_db_exceptions(StructuredNode.save)
        NodeSet.get = catch_db_exceptions(NodeSet.get)

        self.db = db
        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:

        return not self.disconnected
        # if self.disconnected:
        #     return False

        # from neo4j.exceptions import TransientError
        # try:
        #     self.db.driver.verify_connectivity()
        #     return True
        # except (ServiceUnavailable, TransientError) as e:
        #     log.error(e)
        #     return False

    def initialize(self) -> None:

        if self.app:
            with self.app.app_context():
                try:
                    remove_all_labels()
                # With Neo4j 4.3 remove all labels on empty DB started to fail with:
                # [...]
                #   File "/usr/local/lib/python3.9/dist-packages/neomodel/core.py", ...
                #                                           ... line 62, in drop_indexes
                #     index[7][0], index[8][0]))
                # IndexError: list index out of range
                # Maybe that a future release of neomdel will fix the issue
                # and the try/except will be no longer needed
                # It maily fails on NIG when executing init_hpo.sh
                except IndexError as e:  # pragma: no cover
                    log.warning("Can't remove label, is database empty?")
                    log.error(e)

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
    # Argument 1 to "update_properties" becomes "Any" due to an unfollowed import
    def update_properties(instance: StructuredNode, properties: Dict[str, Any]) -> None:  # type: ignore

        for field, value in properties.items():
            instance.__dict__[field] = value

    @catch_db_exceptions
    def cypher(self, query: str, **parameters: str) -> Any:
        """Execute raw cypher queries"""

        try:
            # results, meta = db.cypher_query(query, parameters)
            results, _ = db.cypher_query(query, parameters)
        except CypherSyntaxError as e:
            log.warning(query)
            log.error(f"Failed to execute Cypher Query\n{e}")
            raise CypherSyntaxError("Failed to execute Cypher Query")
        return results

    @staticmethod
    def sanitize_input(term: str) -> str:
        """
        Strip and clean up terms from special characters. To be used in fuzzy search
        """
        return term.strip().replace("*", "").replace("'", "\\'").replace("~", "")

    @staticmethod
    def fuzzy_tokenize(term: str) -> str:
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
    def __init__(self) -> None:
        self.db: NeoModel = get_instance()

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

    def get_user_group(self, user: User) -> Group:
        return user.belongs_to.single()

    def get_group_members(self, group: Group) -> List[User]:
        return list(group.members)

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
                log.warning(
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

    def save_login(self, username: str, user: Optional[User], failed: bool) -> None:

        date = datetime.now(pytz.utc)
        ip_address = self.get_remote_ip()
        ip_location = self.localize_ip(ip_address)

        login = self.db.Login()
        login.date = date
        login.username = username
        login.IP = ip_address
        login.location = ip_location or "Unknown"
        login.failed = failed
        # i.e. failed logins are not flushed by default
        # success logins are automatically flushed
        login.flushed = not failed

        login.save()
        if user:
            login.user.connect(user)

    def get_logins(
        self, username: Optional[str] = None, only_unflushed: bool = False
    ) -> List[Login]:

        if not username:
            logins = self.db.Login.nodes.all()
        elif only_unflushed:
            logins = self.db.Login.nodes.filter(username=username, flushed=False)
        else:
            logins = self.db.Login.nodes.filter(username=username)

        return [x for x in logins]

    def flush_failed_logins(self, username: str) -> None:

        for login in self.db.Login.nodes.filter(username=username, flushed=False):
            login.flushed = True
            login.save()


instance = NeoModel()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: str,
) -> "NeoModel":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
