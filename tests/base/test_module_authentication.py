import time

import pytest

from restapi.env import Env
from restapi.exceptions import RestApiException
from restapi.services.detect import detector
from restapi.tests import BaseTests
from restapi.utilities.logs import log


class TestApp(BaseTests):
    def test_authentication_service(self, client, fake):

        if not detector.check_availability("authentication"):
            log.warning("Skipping authentication test: service not available")
            return False

        auth = detector.get_service_instance("authentication")

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
            pytest.fail("None password!")
        except RestApiException as e:
            assert e.status_code == 400
            assert str(e) == "Missing new password"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            auth.change_password(user, pwd, pwd, None)
            pytest.fail("None password!")
        except RestApiException as e:
            assert e.status_code == 400
            assert str(e) == "Missing password confirmation"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            # wrong confirmation
            auth.change_password(user, pwd, pwd, fake.password(strong=True))
            pytest.fail("wrong password confirmation!?")
        except RestApiException as e:
            assert e.status_code == 409
            assert str(e) == "Your password doesn't match the confirmation"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            auth.change_password(user, pwd, pwd, pwd)
            pytest.fail("Password strength not verified")
        except RestApiException as e:
            assert e.status_code == 409
            assert str(e) == "The new password cannot match the previous password"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            # the first password parameter is only checked for new password strenght
            # i.e. is verified password != newpassword
            # password validity will be checked once completed checks on new password
            # => a random current password is ok here
            auth.change_password(user, fake.password(), pwd, pwd)
            pytest.fail("Password strength not verified")
        except RestApiException as e:
            assert e.status_code == 409
            assert (
                str(e)
                == f"Password is too short, use at least {min_pwd_len} characters"
            )
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            auth.verify_totp(None, None)
            pytest.fail("NULL totp accepted!")
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Invalid verification code"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        # import here to prevent loading before initializing things...
        from restapi.services.authentication import (
            BaseAuthentication,
            InvalidToken,
            Role,
        )

        auth = detector.get_service_instance("authentication")

        pwd1 = fake.password(strong=True)
        pwd2 = fake.password(strong=True)

        hash_1 = auth.get_password_hash(pwd1)
        assert len(hash_1) > 0
        assert hash_1 != auth.get_password_hash(pwd2)

        try:
            auth.get_password_hash("")
            pytest.fail("Hashed a empty password!")
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Invalid password"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        try:
            auth.get_password_hash(None)
            pytest.fail("Hashed a None password!")
        except RestApiException as e:
            assert e.status_code == 401
            assert str(e) == "Invalid password"
        except BaseException:
            pytest.fail("Unexpected exception raised")

        assert auth.verify_password(pwd1, hash_1)
        try:
            auth.verify_password(None, hash_1)
            pytest.fail("Hashed a None password!")
        except TypeError:
            pass
        except BaseException:
            pytest.fail("Unexpected exception raised")

        assert not auth.verify_password(pwd1, None)

        assert not auth.verify_password(None, None)

        ip_data = auth.localize_ip("8.8.8.8")

        assert ip_data is not None
        # I don't know if this tests will be stable...
        assert ip_data == "United States"

        assert auth.localize_ip("8.8.8.8, 4.4.4.4") is None

        def verify_token_is_valid(token, ttype=None):
            unpacked_token = auth.verify_token(token, token_type=ttype)
            assert unpacked_token[0]
            assert unpacked_token[1] is not None
            assert unpacked_token[2] is not None
            assert unpacked_token[3] is not None

        def verify_token_is_not_valid(token, ttype=None):
            unpacked_token = auth.verify_token(token, token_type=ttype)
            assert not unpacked_token[0]
            assert unpacked_token[1] is None
            assert unpacked_token[2] is None
            assert unpacked_token[3] is None

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
        verify_token_is_not_valid(fake.pystr())
        verify_token_is_not_valid(fake.pystr(), auth.PWD_RESET)
        verify_token_is_not_valid(fake.pystr(), auth.ACTIVATE_ACCOUNT)

        user = auth.get_user(username=BaseAuthentication.default_user)
        t1, payload1 = auth.create_temporary_token(user, auth.PWD_RESET)
        assert isinstance(t1, str)
        # not valid if not saved
        verify_token_is_not_valid(t1, auth.PWD_RESET)
        auth.save_token(user, t1, payload1, token_type=auth.PWD_RESET)
        verify_token_is_not_valid(t1)
        verify_token_is_not_valid(t1, auth.FULL_TOKEN)
        verify_token_is_valid(t1, auth.PWD_RESET)
        verify_token_is_not_valid(t1, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(fake.ascii_email(), t1)

        # Create another type of temporary token => t1 is still valid
        t2, payload2 = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT)
        assert isinstance(t2, str)
        # not valid if not saved
        verify_token_is_not_valid(t2, auth.ACTIVATE_ACCOUNT)
        auth.save_token(user, t2, payload2, token_type=auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(t2)
        verify_token_is_not_valid(t2, auth.FULL_TOKEN)
        verify_token_is_not_valid(t2, auth.PWD_RESET)
        verify_token_is_valid(t2, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(fake.ascii_email(), t2)

        EXPIRATION = 3
        # Create another token PWD_RESET, this will invalidate t1
        t3, payload3 = auth.create_temporary_token(
            user, auth.PWD_RESET, duration=EXPIRATION
        )
        assert isinstance(t3, str)
        # not valid if not saved
        verify_token_is_not_valid(t3, auth.PWD_RESET)
        auth.save_token(user, t3, payload3, token_type=auth.PWD_RESET)
        verify_token_is_valid(t3, auth.PWD_RESET)
        verify_token_is_not_valid(t1)
        verify_token_is_not_valid(t1, auth.FULL_TOKEN)
        verify_token_is_not_valid(t1, auth.PWD_RESET)
        verify_token_is_not_valid(t1, auth.ACTIVATE_ACCOUNT)

        # Create another token ACTIVATE_ACCOUNT, this will invalidate t2
        t4, payload4 = auth.create_temporary_token(
            user, auth.ACTIVATE_ACCOUNT, duration=EXPIRATION
        )
        assert isinstance(t4, str)
        # not valid if not saved
        verify_token_is_not_valid(t4, auth.ACTIVATE_ACCOUNT)
        auth.save_token(user, t4, payload4, token_type=auth.ACTIVATE_ACCOUNT)
        verify_token_is_valid(t4, auth.ACTIVATE_ACCOUNT)
        verify_token_is_not_valid(t2)
        verify_token_is_not_valid(t2, auth.FULL_TOKEN)
        verify_token_is_not_valid(t2, auth.PWD_RESET)
        verify_token_is_not_valid(t2, auth.ACTIVATE_ACCOUNT)

        # token expiration is only 3 seconds... let's test it
        time.sleep(EXPIRATION + 1)
        verify_token_is_not_valid(t3, auth.PWD_RESET)
        verify_token_is_not_valid(t4, auth.ACTIVATE_ACCOUNT)

        unpacked_token = auth.verify_token(None, raiseErrors=False)
        assert not unpacked_token[0]
        try:
            auth.verify_token(None, raiseErrors=True)
            pytest.fail("No exception raised!")
        except InvalidToken as e:
            assert str(e) == "Missing token"
        except BaseException:
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

        # assert auth.delete_user(user)
        # assert auth.delete_group(group)

        # # Verify that user/group are now deleted
        # user = auth.get_user(username=BaseAuthentication.default_user)
        # assert user is None
        # group = auth.get_group(name="Default")
        # assert group is None

        # # Verify that init_auth_db will restore default user and group
        # auth.init_auth_db({})
        # user = auth.get_user(username=BaseAuthentication.default_user)
        # assert user is not None
        # group = auth.get_group(name="Default")
        # assert group is not None

        # Modify default user and group
        expected_pwd = BaseAuthentication.get_password_hash(
            BaseAuthentication.default_password
        )
        assert user.password == expected_pwd
        roles = auth.get_roles_from_user(user)
        assert Role.ADMIN in roles

        # Change name, password and roles
        user.name = "Changed"
        user.password = BaseAuthentication.get_password_hash("new-pwd#2!")
        auth.link_roles(user, [Role.USER])
        auth.save_user(user)

        # Change fullname (not the shortname, since it is the primary key)
        group.fullname = "Changed"
        auth.save_group(group)

        # Verify that user and group are changed
        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name == "Changed"
        assert user.password != expected_pwd
        assert Role.ADMIN not in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname == "Changed"

        # Verify that init without force flag will not restore default user and group
        auth.init_auth_db({})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name == "Changed"
        assert user.password != expected_pwd
        assert Role.ADMIN not in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname == "Changed"

        # Verify that init with force flag will not restore the default user and group
        auth.init_auth_db({"force_user": True, "force_group": True})

        user = auth.get_user(username=BaseAuthentication.default_user)
        assert user.name != "Changed"
        assert user.password == expected_pwd
        assert Role.ADMIN in auth.get_roles_from_user(user)

        group = auth.get_group(name="Default")
        assert group.fullname != "Changed"
