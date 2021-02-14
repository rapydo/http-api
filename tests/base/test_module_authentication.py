import time
from typing import Optional

import pytest
from faker import Faker

from restapi.connectors import Connector
from restapi.env import Env
from restapi.exceptions import RestApiException
from restapi.services.authentication import BaseAuthentication
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


class TestApp(BaseTests):
    def test_authentication_service(self, client: FlaskClient, fake: Faker) -> None:

        # Always enable during core tests
        if not Connector.check_availability("authentication"):  # pragma: no cover
            log.warning("Skipping authentication test: service not available")
            return

        auth = Connector.get_authentication_instance()

        min_pwd_len = Env.get_int("AUTH_MIN_PASSWORD_LENGTH", 9999)

        pwd = fake.password(min_pwd_len - 1)
        ret_val, ret_text = auth.verify_password_strength(pwd, pwd)
        assert not ret_val
        assert ret_text == "The new password cannot match the previous password"

        pwd = fake.password(min_pwd_len - 1)
        old_pwd = fake.password(min_pwd_len)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert not ret_val
        error = f"Password is too short, use at least {min_pwd_len} characters"
        assert ret_text == error

        pwd = fake.password(min_pwd_len, low=False, up=True)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert not ret_val
        assert ret_text == "Password is too weak, missing lower case letters"

        pwd = fake.password(min_pwd_len, low=True)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert not ret_val
        assert ret_text == "Password is too weak, missing upper case letters"

        pwd = fake.password(min_pwd_len, low=True, up=True)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert not ret_val
        assert ret_text == "Password is too weak, missing numbers"

        pwd = fake.password(min_pwd_len, low=True, up=True, digits=True)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert not ret_val
        assert ret_text == "Password is too weak, missing special characters"

        pwd = fake.password(min_pwd_len, low=True, up=True, digits=True, symbols=True)
        ret_val, ret_text = auth.verify_password_strength(pwd, old_pwd)
        assert ret_val
        assert ret_text is None

        # How to retrieve a generic user?
        user = None
        pwd = fake.password(min_pwd_len - 1)

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
            auth.change_password(user, pwd, pwd, fake.password(strong=True))
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
            # password validity will be checked once completed checks on new password
            # => a random current password is ok here
            auth.change_password(user, fake.password(), pwd, pwd)
            pytest.fail("Password strength not verified")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 409
            assert (
                str(e)
                == f"Password is too short, use at least {min_pwd_len} characters"
            )
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        try:
            auth.verify_totp(None, None)  # type: ignore
            pytest.fail("NULL totp accepted!")  # pragma: no cover
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Verification code is missing"
        except BaseException:  # pragma: no cover
            pytest.fail("Unexpected exception raised")

        # import here to prevent loading before initializing things...
        from restapi.services.authentication import (
            BaseAuthentication,
            InvalidToken,
            Role,
        )

        auth = Connector.get_authentication_instance()

        pwd1 = fake.password(strong=True)
        pwd2 = fake.password(strong=True)

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

        ip_data = auth.localize_ip("8.8.8.8")

        assert ip_data is not None
        # I don't know if this tests will be stable...
        assert ip_data == "United States"

        assert auth.localize_ip("8.8.8.8, 4.4.4.4") is None

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

        # Test the precedence, username invalid  and user valid => None
        user = auth.get_user(username="invalid", user_id=user.uuid)
        assert user is None

        # None user has no roles ... verify_roles will always be False
        assert not auth.verify_roles(None, ["A", "B"], required_roles="invalid")
        assert not auth.verify_roles(None, ["A", "B"], required_roles="ALL")
        assert not auth.verify_roles(None, ["A", "B"], required_roles="ANY")

        # Just to verify that the function works
        verify_token_is_not_valid(auth, fake.pystr())
        verify_token_is_not_valid(auth, fake.pystr(), auth.PWD_RESET)
        verify_token_is_not_valid(auth, fake.pystr(), auth.ACTIVATE_ACCOUNT)

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
        verify_token_is_not_valid(auth, fake.ascii_email(), t1)

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
        verify_token_is_not_valid(auth, fake.ascii_email(), t2)

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

        # Test GRACE PERIOD for tokens validiy from differt IPs
        # This implementation is partial... at the moment it is not simple to force
        # token save by injecting custom properties
        # Probably this can be useful
        # https://github.com/spulec/freezegun
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

        # init_auth_db should restore missing default user and group. But previous tests
        # created additional users and groups, so that the init auth db without
        # force flags is not able to re-add the missing and user and group
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
        roles = auth.get_roles_from_user(user)
        assert Role.ADMIN.value in roles

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

        # Verify that init without force flag will not restore default user and group
        auth.init_auth_db({})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name == "Changed"
        # assert user.password != expected_pwd
        assert Role.ADMIN.value not in auth.get_roles_from_user(user)
        assert Role.USER.value in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname == "Changed"

        # Verify that init with force flag will not restore the default user and group
        auth.init_auth_db({"force_user": True, "force_group": True})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name != "Changed"
        # assert user.password == expected_pwd
        assert Role.ADMIN.value in auth.get_roles_from_user(user)
        assert Role.USER.value in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname != "Changed"
