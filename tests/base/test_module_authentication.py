import time
from datetime import datetime, timedelta
from typing import Optional

import pyotp
import pytest
import pytz
from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import BadRequest, Conflict, Unauthorized
from restapi.services.authentication import (
    DEFAULT_GROUP_NAME,
    BaseAuthentication,
    InvalidToken,
    Role,
    RoleObj,
)
from restapi.tests import BaseTests, FlaskClient


def verify_token_is_valid(
    auth: BaseAuthentication, token: str, ttype: Optional[str] = None
) -> None:
    unpacked_token = auth.verify_token(token, token_type=ttype)
    assert unpacked_token[0]
    assert unpacked_token[1] is not None
    assert unpacked_token[2] is not None
    assert unpacked_token[3] is not None


def verify_token_is_not_valid(
    auth: BaseAuthentication, token: str, ttype: Optional[str] = None
) -> None:
    unpacked_token = auth.verify_token(token, token_type=ttype)
    assert not unpacked_token[0]
    assert unpacked_token[1] is None
    assert unpacked_token[2] is None
    assert unpacked_token[3] is None

    with pytest.raises(Exception):
        auth.verify_token(token, token_type=ttype, raiseErrors=True)


@pytest.mark.skipif(
    not Connector.check_availability("authentication"),
    reason="This test needs authentication to be available",
)
class TestApp(BaseTests):
    def test_password_management(self, faker: Faker) -> None:
        # Ensure name and surname longer than 3
        name = self.get_first_name(faker)
        surname = self.get_last_name(faker)
        # Ensure an email not containing name and surname
        email = self.get_random_email(faker, name, surname)

        auth = Connector.get_authentication_instance()

        min_pwd_len = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 9999)

        pwd = faker.password(min_pwd_len - 1)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        assert ret_text == "The new password cannot match the previous password"

        pwd = faker.password(min_pwd_len - 1)
        old_pwd = faker.password(min_pwd_len)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        error = f"Password is too short, use at least {min_pwd_len} characters"
        assert ret_text == error

        pwd = faker.password(min_pwd_len, low=False, up=True)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        assert ret_text == "Password is too weak, missing lower case letters"

        pwd = faker.password(min_pwd_len, low=True)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        assert ret_text == "Password is too weak, missing upper case letters"

        pwd = faker.password(min_pwd_len, low=True, up=True)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        assert ret_text == "Password is too weak, missing numbers"

        pwd = faker.password(min_pwd_len, low=True, up=True, digits=True)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert not ret_val
        assert ret_text == "Password is too weak, missing special characters"

        pwd = faker.password(min_pwd_len, low=True, up=True, digits=True, symbols=True)
        ret_val, ret_text = auth.verify_password_strength(
            pwd=pwd, old_pwd=old_pwd, email=email, name=name, surname=surname
        )
        assert ret_val
        assert ret_text == ""

        password_with_name = [
            name,
            surname,
            f"{faker.pystr()}{name}{faker.pystr()}"
            f"{faker.pystr()}{surname}{faker.pystr()}"
            f"{name}{faker.pyint(1, 99)}",
        ]
        for p in password_with_name:
            for pp in [p, p.lower(), p.upper(), p.title()]:
                # This is because with "strange characters" it is not ensured that:
                # str == str.upper().lower()
                # In that case let's skip the variant that alter the characters
                if p.lower() != pp.lower():  # pragma: no cover
                    continue
                # This is to prevent failures for other reasons like length of chars
                pp += "+ABCabc123!"
                val, text = auth.verify_password_strength(
                    pwd=pp, old_pwd=old_pwd, email=email, name=name, surname=surname
                )
                assert not val
                assert text == "Password is too weak, can't contain your name"

        email_local = email.split("@")[0]
        password_with_email = [
            email,
            email.replace(".", "").replace("_", ""),
            email_local,
            email_local.replace(".", "").replace("_", ""),
            f"{faker.pystr()}{email_local}{faker.pystr()}",
        ]

        for p in password_with_email:
            for pp in [p, p.lower(), p.upper(), p.title()]:
                # This is because with "strange characters" it is not ensured that:
                # str == str.upper().lower()
                # In that case let's skip the variant that alter the characters
                if p.lower() != pp.lower():  # pragma: no cover
                    continue
                # This is to prevent failures for other reasons like length of chars
                pp += "+ABCabc123!"
                val, txt = auth.verify_password_strength(
                    pwd=pp, old_pwd=old_pwd, email=email, name=name, surname=surname
                )
                assert not val
                assert txt == "Password is too weak, can't contain your email address"

        # Short names are not inspected for containing checks
        ret_val, ret_text = auth.verify_password_strength(
            pwd="Bob1234567!", old_pwd=old_pwd, email=email, name="Bob", surname=surname
        )
        assert ret_val
        assert ret_text == ""

        user = auth.get_user(username=BaseAuthentication.default_user)
        pwd = faker.password(min_pwd_len - 1)

        with pytest.raises(BadRequest, match=r"Missing new password"):
            # None password
            auth.change_password(user, pwd, None, None)

        with pytest.raises(BadRequest, match=r"Missing password confirmation"):
            # None password confirmation
            auth.change_password(user, pwd, pwd, None)

        with pytest.raises(
            Conflict, match=r"Your password doesn't match the confirmation"
        ):
            # wrong confirmation
            auth.change_password(user, pwd, pwd, faker.password(strong=True))

        with pytest.raises(
            Conflict,
            match=r"The new password cannot match the previous password",
        ):
            # Failed password strength checks
            auth.change_password(user, pwd, pwd, pwd)

        with pytest.raises(
            Conflict,
            match=rf"Password is too short, use at least {min_pwd_len} characters",
        ):
            # the first password parameter is only checked for new password strenght
            # i.e. is verified password != newpassword
            # pwd validity will be checked once completed checks on new password
            # => a random current password is ok here
            # Failed password strength checks
            auth.change_password(user, faker.password(), pwd, pwd)

        pwd1 = faker.password(strong=True)
        pwd2 = faker.password(strong=True)

        hash_1 = auth.get_password_hash(pwd1)
        assert len(hash_1) > 0
        assert hash_1 != auth.get_password_hash(pwd2)

        with pytest.raises(Unauthorized, match=r"Invalid password"):
            # Hashing empty password
            auth.get_password_hash("")

        with pytest.raises(Unauthorized, match=r"Invalid password"):
            # Hashing a None password!
            auth.get_password_hash(None)

        assert auth.verify_password(pwd1, hash_1)

        assert not auth.is_bcrypt_hashed("test")
        test_hash = auth.get_password_hash(pwd1)
        assert auth.is_bcrypt_hashed(test_hash)

    @staticmethod
    @pytest.mark.skipif(
        not Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"),
        reason="This test needs 2FA to be available",
    )
    def test_totp_management() -> None:
        auth = Connector.get_authentication_instance()

        with pytest.raises(Unauthorized, match=r"Verification code is missing"):
            # NULL totp
            auth.verify_totp(None, None)

        user = auth.get_user(username=auth.default_user)
        secret = auth.get_totp_secret(user)
        totp = pyotp.TOTP(secret)

        # Verifiy current totp
        assert auth.verify_totp(user, totp.now())

        now = datetime.now()
        t30s = timedelta(seconds=30)

        # Verify previous and next totp(s)
        assert auth.verify_totp(user, totp.at(now + t30s))
        assert auth.verify_totp(user, totp.at(now - t30s))

        # Verify second-previous and second-ntext totp(s)
        with pytest.raises(Unauthorized, match=r"Verification code is not valid"):
            # Future totp
            auth.verify_totp(user, totp.at(now + t30s + t30s))

        with pytest.raises(Unauthorized, match=r"Verification code is not valid"):
            # Past totp
            auth.verify_totp(user, totp.at(now - t30s - t30s))

        # Extend validity window
        auth.TOTP_VALIDITY_WINDOW = 2

        # Verify again second-previous and second-ntext totp(s)
        assert auth.verify_totp(user, totp.at(now + t30s + t30s))
        assert auth.verify_totp(user, totp.at(now - t30s - t30s))

        # Verify second-second-previous and second-second-ntext totp(s)
        with pytest.raises(Unauthorized, match=r"Verification code is not valid"):
            # Future totp
            auth.verify_totp(user, totp.at(now + t30s + t30s + t30s))

        with pytest.raises(Unauthorized, match=r"Verification code is not valid"):
            # Past totp
            auth.verify_totp(user, totp.at(now - t30s - t30s - t30s))

    @staticmethod
    def test_login_management(faker: Faker) -> None:
        auth = Connector.get_authentication_instance()

        if BaseAuthentication.default_user:
            logins = auth.get_logins(BaseAuthentication.default_user)

            assert isinstance(logins, list)
            assert len(logins) > 0

            auth.flush_failed_logins(BaseAuthentication.default_user)
            logins = auth.get_logins(
                BaseAuthentication.default_user, only_unflushed=True
            )
            assert len(logins) == 0

            logins = auth.get_logins(
                BaseAuthentication.default_user, only_unflushed=False
            )
            assert len(logins) > 0

        logins = auth.get_logins(faker.ascii_email())
        assert isinstance(logins, list)
        assert len(logins) == 0

        logins = auth.get_logins(faker.pystr())
        assert isinstance(logins, list)
        assert len(logins) == 0

    def test_tokens_management(self, client: FlaskClient, faker: Faker) -> None:
        auth = Connector.get_authentication_instance()

        # Just to verify that the function works
        verify_token_is_not_valid(auth, faker.pystr())
        verify_token_is_not_valid(auth, faker.pystr(), auth.PWD_RESET)
        verify_token_is_not_valid(auth, faker.pystr(), auth.ACTIVATE_ACCOUNT)

        user = auth.get_user(username=BaseAuthentication.default_user)
        t1, payload1 = auth.create_temporary_token(user, auth.PWD_RESET)
        assert isinstance(t1, str)
        # not valid if not saved
        verify_token_is_not_valid(auth, t1, auth.PWD_RESET)
        auth.save_token(user, t1, payload1, token_type=auth.PWD_RESET)
        verify_token_is_not_valid(auth, t1)
        verify_token_is_not_valid(auth, t1, auth.FULL_TOKEN)
        verify_token_is_valid(auth, t1, auth.PWD_RESET)
        verify_token_is_not_valid(auth, t1, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(auth, faker.ascii_email(), t1)

        # Create another type of temporary token => t1 is still valid
        t2, payload2 = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT)
        assert isinstance(t2, str)
        # not valid if not saved
        verify_token_is_not_valid(auth, t2, auth.ACTIVATE_ACCOUNT)
        auth.save_token(user, t2, payload2, token_type=auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(auth, t2)
        verify_token_is_not_valid(auth, t2, auth.FULL_TOKEN)
        verify_token_is_not_valid(auth, t2, auth.PWD_RESET)
        verify_token_is_valid(auth, t2, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(auth, faker.ascii_email(), t2)

        EXPIRATION = 3
        # Create another token PWD_RESET, this will invalidate t1
        t3, payload3 = auth.create_temporary_token(
            user, auth.PWD_RESET, duration=EXPIRATION
        )
        assert isinstance(t3, str)
        # not valid if not saved
        verify_token_is_not_valid(auth, t3, auth.PWD_RESET)
        auth.save_token(user, t3, payload3, token_type=auth.PWD_RESET)
        verify_token_is_valid(auth, t3, auth.PWD_RESET)
        verify_token_is_not_valid(auth, t1)
        verify_token_is_not_valid(auth, t1, auth.FULL_TOKEN)
        verify_token_is_not_valid(auth, t1, auth.PWD_RESET)
        verify_token_is_not_valid(auth, t1, auth.ACTIVATE_ACCOUNT)

        # Create another token ACTIVATE_ACCOUNT, this will invalidate t2
        t4, payload4 = auth.create_temporary_token(
            user, auth.ACTIVATE_ACCOUNT, duration=EXPIRATION
        )
        assert isinstance(t4, str)
        # not valid if not saved
        verify_token_is_not_valid(auth, t4, auth.ACTIVATE_ACCOUNT)
        auth.save_token(user, t4, payload4, token_type=auth.ACTIVATE_ACCOUNT)
        verify_token_is_valid(auth, t4, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(auth, t2)
        verify_token_is_not_valid(auth, t2, auth.FULL_TOKEN)
        verify_token_is_not_valid(auth, t2, auth.PWD_RESET)
        verify_token_is_not_valid(auth, t2, auth.ACTIVATE_ACCOUNT)

        # token expiration is only 3 seconds... let's test it
        time.sleep(EXPIRATION + 1)
        verify_token_is_not_valid(auth, t3, auth.PWD_RESET)
        verify_token_is_not_valid(auth, t4, auth.ACTIVATE_ACCOUNT)

        unpacked_token = auth.verify_token(None, raiseErrors=False)
        assert not unpacked_token[0]

        with pytest.raises(InvalidToken, match=r"Missing token"):
            auth.verify_token(None, raiseErrors=True)

        # Test token validiy
        _, token = self.do_login(client, None, None)

        tokens = auth.get_tokens(get_all=True)
        jti = None
        user = None
        for t in tokens:
            if t["token"] == token:
                jti = t["id"]
                user = t["user"]
                break
        assert jti is not None
        assert user is not None

        assert auth.verify_token_validity(jti, user)

        # Verify token against a wrong user
        group = auth.get_group(name=DEFAULT_GROUP_NAME)
        another_user = auth.create_user(
            {
                "email": faker.ascii_email(),
                "name": "Default",
                "surname": "User",
                "password": faker.password(strong=True),
                "last_password_change": datetime.now(pytz.utc),
            },
            # It will be expanded with the default role
            roles=[],
            group=group,
        )
        auth.save_user(another_user)

        assert not auth.verify_token_validity(jti, another_user)

    @staticmethod
    def test_users_groups_roles(faker: Faker) -> None:
        auth = Connector.get_authentication_instance()

        user = auth.get_user(username=BaseAuthentication.default_user)
        group = auth.get_group(name="Default")
        assert user is not None

        user = auth.get_user(user_id=user.uuid)
        assert user is not None

        user = auth.get_user(username="invalid")
        assert user is None

        user = auth.get_user(user_id="invalid")
        assert user is None

        user = auth.get_user(username=None, user_id=None)
        assert user is None

        # Test the precedence, username valid  and user invalid => user
        user = auth.get_user(
            username=BaseAuthentication.default_user, user_id="invalid"
        )
        assert user is not None

        # Test the precedence, username invalid and user valid => None
        user = auth.get_user(username="invalid", user_id=user.uuid)
        assert user is None

        assert auth.get_user(None, None) is None
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is not None
        assert not auth.save_user(None)
        assert auth.save_user(user)
        assert not auth.delete_user(None)

        assert auth.get_group(None, None) is None
        group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert group is not None
        assert not auth.save_group(None)
        assert auth.save_group(group)
        assert not auth.delete_group(None)

        # None user has no roles ... verify_roles will always be False
        assert not auth.verify_roles(None, ["A", "B"], required_roles="invalid")
        assert not auth.verify_roles(None, ["A", "B"], required_roles="ALL")
        assert not auth.verify_roles(None, ["A", "B"], required_roles="ANY")

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user is not None
        group = auth.get_group(name="Default")
        assert group is not None

        assert not auth.delete_user(None)
        assert not auth.delete_group(None)

        # Delete default user, default group and all users belonging to it
        members = auth.get_group_members(group)
        for u in members:
            assert auth.delete_user(u)
        assert auth.delete_user(user)
        assert auth.delete_group(group)

        # Verify that both user and group are now deleted
        assert auth.get_user(username=BaseAuthentication.default_user) is None
        assert auth.get_group(name="Default") is None

        # init_auth_db should restore missing default user and group.
        # But previous tests created additional users and groups, so that
        # the init auth db without force flags is not able to re-add
        # the missing and user and group
        if Env.get_bool("MAIN_LOGIN_ENABLE"):
            auth.init_auth_db({})
            assert auth.get_user(username=BaseAuthentication.default_user) is None
            assert auth.get_group(name="Default") is None

        # Let's add the force flags to re-create the default user and group
        auth.init_auth_db({"force_user": True, "force_group": True})
        assert auth.get_user(username=BaseAuthentication.default_user) is not None
        assert auth.get_group(name="Default") is not None

        # Let's save the current password to be checked later
        user = auth.get_user(username=BaseAuthentication.default_user)
        # expected_pwd = user.password
        # Let's verify that the user now is ADMIN
        assert Role.ADMIN.value in auth.get_roles_from_user(user)

        # Modify default user and group
        # # Change name, password and roles
        user.name = "Changed"
        # user.password = BaseAuthentication.get_password_hash("new-pwd#2!")
        auth.link_roles(user, [Role.USER.value])
        auth.save_user(user)

        # Change fullname (not the shortname, since it is the primary key)
        group = auth.get_group(name="Default")
        group.fullname = "Changed"
        auth.save_group(group)

        # Verify that user and group are changed
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name == "Changed"
        # assert user.password != expected_pwd
        assert Role.ADMIN.value not in auth.get_roles_from_user(user)
        assert Role.USER.value in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname == "Changed"

        roles: list[RoleObj] = auth.get_roles()
        assert isinstance(roles, list)
        assert len(roles) > 0

        # Pick one of the default roles and change the description
        role: RoleObj = roles[0]
        assert role is not None
        default_name = role.name
        default_description = role.description
        new_description = faker.pystr()
        role.description = new_description
        assert auth.save_role(role)
        assert not auth.save_role(None)

        # Create a new custom role
        new_role_name = faker.pystr()
        new_role_descr = faker.pystr()
        auth.create_role(name=new_role_name, description=new_role_descr)

        # Verify the change on the roles and the creation of the new one
        for r in auth.get_roles():
            if r.name == default_name:
                assert r.description == new_description
                assert r.description != default_description

            if r.name == new_role_name:
                assert r.description == new_role_descr

        # Verify that duplicated role names are refused at init time
        roles_data_backup = auth.roles_data
        auth.roles_data = {
            "admin_root": "Admin",
            "staff_user": "Coordinator",
            "group_coordinator": "Coordinator",
            "normal_user": "User",
        }
        with pytest.raises(SystemExit):
            auth.init_roles()

        auth.roles_data = roles_data_backup

        # Verify that init_roles restores description of default roles
        # While custom roles are not modified
        auth.init_roles()

        for r in auth.get_roles():
            # default description restored for this default role
            if r.name == default_name:
                assert r.description != new_description
                assert r.description == default_description

            # custom additional role not modified by init roles
            if r.name == new_role_name:
                assert r.description == new_role_descr

        # Verify init without force flag will not restore default user and group
        auth.init_auth_db({})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name == "Changed"
        # assert user.password != expected_pwd
        assert Role.ADMIN.value not in auth.get_roles_from_user(user)
        assert Role.USER.value in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname == "Changed"

        # Verify init with force flag will not restore the default user and group
        auth.init_auth_db({"force_user": True, "force_group": True})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name != "Changed"
        # assert user.password == expected_pwd
        assert Role.ADMIN.value in auth.get_roles_from_user(user)
        assert Role.USER.value in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname != "Changed"

    @staticmethod
    def test_authentication_abstract_methods(faker: Faker) -> None:
        # Super trick!
        # https://clamytoe.github.io/articles/2020/Mar/12/testing-abcs-with-abstract-methods-with-pytest
        abstractmethods = BaseAuthentication.__abstractmethods__
        BaseAuthentication.__abstractmethods__ = frozenset()

        auth = Connector.get_authentication_instance()
        user = auth.get_user(username=BaseAuthentication.default_user)
        group = auth.get_group(name=DEFAULT_GROUP_NAME)
        role = auth.get_roles()[0]

        auth = BaseAuthentication()  # type: ignore

        assert (
            auth.get_user(username=faker.ascii_email(), user_id=faker.pystr()) is None
        )

        assert auth.get_users() is None
        assert auth.save_user(user=user) is None
        assert auth.delete_user(user=user) is None

        assert auth.get_group(group_id=faker.pystr(), name=faker.pystr()) is None

        assert auth.get_groups() is None
        assert auth.get_user_group(user=user) is None

        assert auth.get_group_members(group=group) is None

        assert auth.save_group(group=group) is None

        assert auth.delete_group(group=group) is None

        assert auth.get_tokens(user=user, token_jti=faker.pystr(), get_all=True) is None

        assert auth.verify_token_validity(jti=faker.pystr(), user=user) is None

        assert (
            auth.save_token(
                user=user, token=faker.pystr(), payload={}, token_type=faker.pystr()
            )
            is None
        )

        assert auth.invalidate_token(token=faker.pystr()) is None

        assert auth.get_roles() is None

        assert auth.get_roles_from_user(user=user) is None

        assert auth.create_role(name=faker.pystr(), description=faker.pystr()) is None
        assert auth.save_role(role=role) is None

        group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert auth.create_user(userdata={}, roles=[faker.pystr()], group=group) is None

        assert auth.link_roles(user=user, roles=[faker.pystr()]) is None
        assert auth.create_group(groupdata={}) is None

        assert auth.add_user_to_group(user=user, group=group) is None

        assert (
            auth.save_login(username=faker.ascii_email(), user=user, failed=True)
            is None
        )
        assert (
            auth.save_login(username=faker.ascii_email(), user=None, failed=True)
            is None
        )
        assert (
            auth.save_login(username=faker.ascii_email(), user=user, failed=False)
            is None
        )
        assert (
            auth.save_login(username=faker.ascii_email(), user=None, failed=False)
            is None
        )

        assert auth.get_logins(username=faker.ascii_email) is None

        assert auth.flush_failed_logins(username=faker.ascii_email) is None

        BaseAuthentication.__abstractmethods__ = abstractmethods
