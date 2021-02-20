import re
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional, Union

from pymodm import MongoModel
from pymodm import connection as mongodb
from pymodm.base.models import TopLevelMongoModel
from pymongo.errors import DuplicateKeyError, ServerSelectionTimeoutError

from restapi.connectors import Connector
from restapi.exceptions import BadRequest, DatabaseDuplicatedEntry
from restapi.services.authentication import (
    BaseAuthentication,
    Group,
    Payload,
    RoleObj,
    Token,
    User,
)
from restapi.utilities.logs import Events, log
from restapi.utilities.uuid import getUUID


def catch_db_exceptions(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        try:
            return func(*args, **kwargs)

        except DatabaseDuplicatedEntry as e:
            # already catched and parser, raise up
            raise (e)

        except DuplicateKeyError as e:

            regexp = fr".+ duplicate key error collection: {MongoExt.DATABASE}\."
            regexp += r"(.+) index: .+ dup key: { (.+): \"(.+)\" }"
            m = re.search(regexp, str(e))
            if m:
                node = m.group(1)
                prop = m.group(2)
                val = m.group(3)
                error = f"A {node.title()} already exists with {prop}: {val}"

                raise DatabaseDuplicatedEntry(error)

            # Can't be tested, should never happen except in case of new mongo version
            log.error("Unrecognized error message: {}", e)  # pragma: no cover
            raise DatabaseDuplicatedEntry("Duplicated entry")  # pragma: no cover

        # except ValidationError as e:
        #     # not handled
        #     raise e
        except RecursionError as e:  # pragma: no cover
            # Got some circular references? Let's try to break them,
            # but the cause is still unknown...
            raise BadRequest(str(e))

        except BaseException as e:  # pragma: no cover
            log.critical("Raised unknown exception: {}", type(e))
            raise e

    return wrapper


class MongoExt(Connector):

    DATABASE: str = "rapydo"

    # This is used to return Models in a type-safe way
    def __getattr__(self, name: str) -> MongoModel:
        if name in self._models:
            return self._models[name]
        raise AttributeError(f"Model {name} not found")

    def get_connection_exception(self):
        return (ServerSelectionTimeoutError,)

    @staticmethod
    def _get_uri(variables):
        HOST = variables.get("host")
        PORT = variables.get("port")
        USER = variables.get("user")
        PWD = variables.get("password")
        credentials = ""
        if USER and PWD:
            credentials = f"{USER}:{PWD}@"

        return f"mongodb://{credentials}{HOST}:{PORT}/{MongoExt.DATABASE}"

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        MongoExt.DATABASE = variables.get("database", "rapydo")
        uri = self._get_uri(variables)

        mongodb.connect(uri, alias=MongoExt.DATABASE)
        self.connection = mongodb._get_connection(alias=MongoExt.DATABASE)

        TopLevelMongoModel.save = catch_db_exceptions(TopLevelMongoModel.save)

        return self

    def disconnect(self) -> None:
        self.disconnected = True

    def is_connected(self) -> bool:

        log.warning("mongo.is_connected method is not implemented")
        return not self.disconnected

    def initialize(self) -> None:
        pass

    def destroy(self) -> None:

        instance = self.get_instance()

        # massive destruction
        client = instance.connection.database

        from pymongo import MongoClient

        uri = self._get_uri(self.variables)
        client = MongoClient(uri)

        system_dbs = ["admin", "local", "config"]
        for db in client.list_database_names():
            if db not in system_dbs:
                client.drop_database(db)
                log.critical("Dropped db '{}'", db)

    @staticmethod
    def update_properties(instance, properties):

        for field, value in properties.items():
            setattr(instance, field, value)


class Authentication(BaseAuthentication):
    def __init__(self):
        self.db = get_instance()

    # Also used by POST user
    def create_user(self, userdata: Dict[str, Any], roles: List[str]) -> User:

        userdata.setdefault("authmethod", "credentials")
        userdata.setdefault("uuid", getUUID())
        userdata.setdefault("id", userdata["uuid"])

        if "password" in userdata:
            userdata["password"] = self.get_password_hash(userdata["password"])

        userdata, extra_userdata = self.custom_user_properties_pre(userdata)

        user = self.db.User(**userdata)

        self.link_roles(user, roles)

        self.custom_user_properties_post(user, userdata, extra_userdata, self.db)

        user.save()

        return user

    def link_roles(self, user: User, roles: List[str]) -> None:

        if not roles:
            roles = [BaseAuthentication.default_role]

        roles_obj = []
        for role_name in roles:
            role_obj = self.db.Role.objects.get({"name": role_name})
            roles_obj.append(role_obj)
        user.roles = roles_obj

    def create_group(self, groupdata: Dict[str, Any]) -> Group:

        groupdata.setdefault("uuid", getUUID())
        groupdata.setdefault("id", groupdata["uuid"])

        group = self.db.Group(**groupdata)

        group.save()

        return group

    def add_user_to_group(self, user: User, group: Group) -> None:

        if user and group:
            user.belongs_to = group
            user.save()

    def get_user(
        self, username: Optional[str] = None, user_id: Optional[str] = None
    ) -> Optional[User]:

        try:
            if username:
                return self.db.User.objects.raw({"email": username}).first()

            if user_id:
                return self.db.User.objects.get({"uuid": user_id})

        except self.db.User.DoesNotExist:
            log.debug(
                "Could not find user for username={}, user_id={}", username, user_id
            )

        return None

    def get_users(self) -> List[User]:
        return list(self.db.User.objects.all())

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
        try:

            if group_id:
                return self.db.Group.objects.get({"uuid": group_id})

            if name:
                return self.db.Group.objects.raw({"shortname": name}).first()

        except self.db.Group.DoesNotExist:
            log.debug("Could not find group for name={}, group_id={}", name, group_id)

        return None

    def get_groups(self) -> List[Group]:
        return list(self.db.Group.objects.all())

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
        for role_name in self.roles:
            try:
                role = self.db.Role.objects.get({"name": role_name})
                if role:
                    roles.append(role)
            # Can't be tested, since roles are injected at init time
            except self.db.Role.DoesNotExist:  # pragma: no cover
                log.warning("Role not found: {}", role_name)

        return roles

    def get_roles_from_user(self, user: Optional[User]) -> List[str]:

        # No user for non authenticated endpoints -> return no role
        if user is None:
            return []

        return [role.name for role in user.roles]

    def create_role(self, name: str, description: str) -> None:
        role = self.db.Role(name=name, description=description)
        role.save()

    def save_role(self, role: RoleObj) -> bool:
        if not role:
            return False

        role.save()
        return True

    def save_token(
        self, user: User, token: str, payload: Payload, token_type: Optional[str] = None
    ) -> None:

        ip_address = self.get_remote_ip()
        ip_loc = self.localize_ip(ip_address)

        if token_type is None:
            token_type = self.FULL_TOKEN

        now = datetime.now()
        exp = payload.get("exp", now + timedelta(seconds=self.DEFAULT_TOKEN_TTL))

        self.db.Token(
            jti=payload["jti"],
            token=token,
            token_type=token_type,
            creation=now,
            last_access=now,
            expiration=exp,
            IP=ip_address,
            location=ip_loc or "Unknown",
            user_id=user,
        ).save()

        # Save user updated in profile endpoint
        user.save()

    def verify_token_validity(self, jti: str, user: User) -> bool:

        try:
            token_entry = self.db.Token.objects.raw({"jti": jti}).first()
        except self.db.Token.DoesNotExist:
            return False

        if token_entry.user_id is None or token_entry.user_id.email != user.email:
            return False

        now = datetime.now()
        if now > token_entry.expiration:
            self.invalidate_token(token=token_entry.token)
            log.info(
                "This token is no longer valid: expired since {}",
                token_entry.expiration.strftime("%d/%m/%Y"),
            )
            return False

        # Verify IP validity only after grace period is expired
        if token_entry.creation + self.GRACE_PERIOD < now:
            ip = self.get_remote_ip()
            if token_entry.IP != ip:
                log.error(
                    "This token is emitted for IP {}, invalid use from {}",
                    token_entry.IP,
                    ip,
                )
                return False

        if token_entry.last_access + self.SAVE_LAST_ACCESS_EVERY < now:
            token_entry.last_access = now
            token_entry.save()

        return True

    def get_tokens(
        self,
        user: Optional[User] = None,
        token_jti: Optional[str] = None,
        get_all: bool = False,
    ) -> List[Token]:

        tokens_list: List[Token] = []
        tokens = []

        if get_all:
            tokens = self.db.Token.objects.all()
        elif user:
            try:
                tokens = self.db.Token.objects.raw({"user_id": user.id}).all()
            except self.db.Token.DoesNotExist:  # pragma: no cover
                pass
        elif token_jti:
            try:
                tokens.append(self.db.Token.objects.raw({"jti": token_jti}).first())
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
                    t["user"] = token.user_id
                tokens_list.append(t)

        return tokens_list

    def invalidate_token(self, token: str) -> bool:
        try:
            token_entry = self.db.Token.objects.raw({"token": token}).first()
            token_entry.delete()

            self.log_event(Events.delete, target=token_entry)

        except self.db.Token.DoesNotExist:
            log.warning("Could not invalidate non-existing token")

        return True


instance = MongoExt()


def get_instance(
    verification: Optional[int] = None,
    expiration: Optional[int] = None,
    **kwargs: Union[Optional[str], int],
) -> "MongoExt":

    return instance.get_instance(
        verification=verification, expiration=expiration, **kwargs
    )
