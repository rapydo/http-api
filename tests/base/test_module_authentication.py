import time
from datetime import datetime, timedelta
from typing import List, Optional

import pyotp
import pytest
import pytz
from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import RestApiException
from restapi.services.authentication import (
    DEFAULT_GROUP_NAME,
    BaseAuthentication,
    InvalidToken,
    Role,
    RoleObj,
)
from restapi.tests import BaseTests, FlaskClient
from restapi.utilities.logs import log


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

    try:
        auth.verify_token(token, token_type=ttype, raiseErrors=True)
        pytest.fail("No exception raised")  # pragma: no cover
    except BaseException:
        pass


class TestApp(BaseTests):
    def test_password_management(self, faker: Faker) -> None:

        if not Connector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return

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

        try:
            auth.change_password(user, pwd, None, None)
            pytest.fail("None password!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 400
            assert str(e) == "Missing new password"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.change_password(user, pwd, pwd, None)
            pytest.fail("None password!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 400
            assert str(e) == "Missing password confirmation"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            # wrong confirmation
            auth.change_password(user, pwd, pwd, faker.password(strong=True))
            pytest.fail("wrong password confirmation!?")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 409
            assert str(e) == "Your password doesn't match the confirmation"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.change_password(user, pwd, pwd, pwd)
            pytest.fail("Password strength not verified")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 409
            assert str(e) == "The new password cannot match the previous password"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            # the first password parameter is only checked for new password strenght
            # i.e. is verified password != newpassword
            # pwd validity will be checked once completed checks on new password
            # => a random current password is ok here
            auth.change_password(user, faker.password(), pwd, pwd)
            pytest.fail("Password strength not verified")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 409
            assert (
                str(e)
                == f"Password is too short, use at least {min_pwd_len} characters"
            )
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        pwd1 = faker.password(strong=True)
        pwd2 = faker.password(strong=True)

        hash_1 = auth.get_password_hash(pwd1)
        assert len(hash_1) > 0
        assert hash_1 != auth.get_password_hash(pwd2)

        try:
            auth.get_password_hash("")
            pytest.fail("Hashed a empty password!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Invalid password"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.get_password_hash(None)
            pytest.fail("Hashed a None password!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Invalid password"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        assert auth.verify_password(pwd1, hash_1)
        try:
            auth.verify_password(None, hash_1)  # type: ignore
            pytest.fail("Hashed a None password!")  # pragma: no cover
        except TypeError:
            pass
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        assert not auth.verify_password(pwd1, None)  # type: ignore

        assert not auth.verify_password(None, None)  # type: ignore

    def test_totp_management(self) -> None:

        if not Env.get_bool("AUTH_SECOND_FACTOR_AUTHENTICATION"):
            log.warning("Skipping TOTP test: 2FA not enabled")
            return

        auth = Connector.get_authentication_instance()

        try:
            auth.verify_totp(None, None)  # type: ignore
            pytest.fail("NULL totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is missing"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

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
        try:
            auth.verify_totp(user, totp.at(now + t30s + t30s))
            pytest.fail("Future totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is not valid"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.verify_totp(user, totp.at(now - t30s - t30s))
            pytest.fail("Past totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is not valid"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        # Extend validity window
        auth.TOTP_VALIDITY_WINDOW = 2

        # Verify again second-previous and second-ntext totp(s)
        assert auth.verify_totp(user, totp.at(now + t30s + t30s))
        assert auth.verify_totp(user, totp.at(now - t30s - t30s))

        # Verify second-second-previous and second-second-ntext totp(s)
        try:
            auth.verify_totp(user, totp.at(now + t30s + t30s + t30s))
            pytest.fail("Future totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is not valid"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.verify_totp(user, totp.at(now - t30s - t30s - t30s))
            pytest.fail("Past totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is not valid"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

    def test_ip_management(self) -> None:

        if not Connector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return

        auth = Connector.get_authentication_instance()

        ip_data = auth.localize_ip("8.8.8.8")

        assert ip_data is not None
        # I don't know if this tests will be stable...
        assert ip_data == "United States"

        assert auth.localize_ip("8.8.8.8, 4.4.4.4") is None

    def test_tokens_management(self, client: FlaskClient, faker: Faker) -> None:

        if not Connector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return

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
        try:
            auth.verify_token(None, raiseErrors=True)
            pytest.fail("No exception raised!")  # pragma: no cover
        except InvalidToken as e:
            assert str(e) == "Missing token"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

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
        )
        auth.save_user(another_user)

        assert not auth.verify_token_validity(jti, another_user)

    def test_users_groups_roles(self, faker: Faker) -> None:

        if not Connector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return

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
        assert not auth.save_user(None)  # type: ignore
        assert auth.save_user(user)
        assert not auth.delete_user(None)  # type: ignore

        assert auth.get_group(None, None) is None
        group = auth.get_group(name=DEFAULT_GROUP_NAME)
        assert group is not None
        assert not auth.save_group(None)  # type: ignore
        assert auth.save_group(group)
        assert not auth.delete_group(None)  # type: ignore

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

        assert auth.delete_user(user)
        assert auth.delete_group(group)

        # Verify that user/group are now deleted
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

        roles: List[RoleObj] = auth.get_roles()
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
        assert not auth.save_role(None)  # type: ignore

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

    def test_authentication_abstract_methods(self, faker: Faker) -> None:

        if not Connector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return

        # Super trick!
        # https://clamytoe.github.io/articles/2020/Mar/12/testing-abcs-with-abstract-methods-with-pytest
        abstractmethods = BaseAuthentication.__abstractmethods__  # type: ignore
        BaseAuthentication.__abstractmethods__ = set()  # type: ignore

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

        assert auth.create_user(userdata={}, roles=[faker.pystr()]) is None

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

        BaseAuthentication.__abstractmethods__ = abstractmethods  # type: ignore
