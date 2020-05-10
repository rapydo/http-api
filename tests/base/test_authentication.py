# -*- coding: utf-8 -*-
import os
import time
import random
import string
import pytest
from restapi.utilities.globals import mem
from restapi.customization import Customizer
from restapi.connectors.authentication import HandleSecurity
from restapi.services.detect import detector
from restapi.exceptions import RestApiException
from restapi.utilities.logs import log


def random_string(length, low=True, up=False, digits=False, symbols=False):
    """
        Create a random string to be used to build data for tests
    """

    charset = ""
    if low:
        charset += string.ascii_lowercase
    if up:
        charset += string.ascii_uppercase
    if digits:
        charset += string.digits
    if symbols:
        charset += string.punctuation

    rand = random.SystemRandom()

    randstr = ''.join(rand.choices(charset, k=length))
    if low and not any(s in randstr for s in string.ascii_lowercase):
        log.warning(
            "String {} not strong enough, missing lower case characters".format(
                randstr
            )
        )
        return random_string(length, low=low, up=up, digits=digits, symbols=symbols)
    if up and not any(s in randstr for s in string.ascii_uppercase):
        log.warning(
            "String {} not strong enough, missing upper case characters".format(
                randstr
            )
        )
        return random_string(length, low=low, up=up, digits=digits, symbols=symbols)
    if digits and not any(s in randstr for s in string.digits):
        log.warning(
            "String {} not strong enough, missing digits".format(
                randstr
            )
        )
        return random_string(length, low=low, up=up, digits=digits, symbols=symbols)
    if symbols and not any(s in randstr for s in string.punctuation):
        log.warning(
            "String {} not strong enough, missing symbols".format(
                randstr
            )
        )
        return random_string(length, low=low, up=up, digits=digits, symbols=symbols)

    return randstr


def test_authentication_connector():

    if not detector.check_availability('authentication'):
        log.warning("Skipping authentication test: service not available")
        return False

    connector = detector.connectors_instances.get('authentication')
    if connector is None:
        log.warning("Skipping authentication test: connector is not available")
        return False

    auth = connector.get_instance()
    security = HandleSecurity(auth)

    min_pwd_len = int(os.environ.get("AUTH_MIN_PASSWORD_LENGTH", 9999))

    pwd = random_string(min_pwd_len - 1)
    ret_val, ret_text = security.verify_password_strength(pwd, old_pwd=pwd)
    assert not ret_val
    assert ret_text == 'The new password cannot match the previous password'

    pwd = random_string(min_pwd_len - 1)
    old_pwd = random_string(min_pwd_len)
    ret_val, ret_text = security.verify_password_strength(pwd, old_pwd=old_pwd)
    assert not ret_val
    assert ret_text == 'Password is too short, use at least {} characters'.format(
        min_pwd_len
    )

    pwd = random_string(min_pwd_len, low=False, up=True)
    ret_val, ret_text = security.verify_password_strength(pwd)
    assert not ret_val
    assert ret_text == 'Password is too weak, missing lower case letters'

    pwd = random_string(min_pwd_len, low=True)
    ret_val, ret_text = security.verify_password_strength(pwd)
    assert not ret_val
    assert ret_text == 'Password is too weak, missing upper case letters'

    pwd = random_string(min_pwd_len, low=True, up=True)
    ret_val, ret_text = security.verify_password_strength(pwd)
    assert not ret_val
    assert ret_text == 'Password is too weak, missing numbers'

    pwd = random_string(min_pwd_len, low=True, up=True, digits=True)
    ret_val, ret_text = security.verify_password_strength(pwd)
    assert not ret_val
    assert ret_text == 'Password is too weak, missing special characters'

    pwd = random_string(min_pwd_len, low=True, up=True, digits=True, symbols=True)
    ret_val, ret_text = security.verify_password_strength(pwd)
    assert ret_val
    assert ret_text is None

    # How to retrieve a generic user?
    user = None
    pwd = random_string(min_pwd_len - 1)

    try:
        security.change_password(user, pwd, None, None)
        pytest.fail('None password!')
    except RestApiException as e:
        assert e.status_code == 400
        assert str(e) == "Wrong new password"

    try:
        security.change_password(user, pwd, pwd, None)
        pytest.fail('None password!')
    except RestApiException as e:
        assert e.status_code == 400
        assert str(e) == "Wrong password confirm"

    try:
        security.change_password(user, pwd, pwd, 'wrongconfirmation')
        pytest.fail('wrong passwrd confirmation!?')
    except RestApiException as e:
        assert e.status_code == 409
        assert str(e) == "Your password doesn't match the confirmation"

    try:
        security.change_password(user, pwd, pwd, pwd)
        pytest.fail('Password strength not verified')
    except RestApiException as e:
        assert e.status_code == 409
        assert str(e) == 'The new password cannot match the previous password'

    try:
        security.change_password(user, "currentpassword", pwd, pwd)
        pytest.fail('Password strength not verified')
    except RestApiException as e:
        assert e.status_code == 409
        assert str(e) == 'Password is too short, use at least {} characters'.format(
            min_pwd_len
        )

    try:
        security.verify_totp(None, None)
        pytest.fail("NULL totp accepted!")
    except RestApiException as e:
        assert e.status_code == 401
        assert str(e) == 'Invalid verification code'


def test_authentication_service():
    if not detector.check_availability('authentication'):
        log.warning("Skipping authentication test: service not available")
        return False

    db_service = None
    if detector.check_availability('neo4j'):
        from restapi.services.authentication.neo4j import Authentication
        db_service = detector.connectors_instances.get('neo4j').get_instance()

    elif detector.check_availability('sqlalchemy'):
        from restapi.services.authentication.sqlalchemy import Authentication
        db_service = detector.connectors_instances.get('sqlalchemy').get_instance()

    elif detector.check_availability('mongo'):
        from restapi.services.authentication.mongo import Authentication
        db_service = detector.connectors_instances.get('mongo').get_instance()

    else:
        log.warning("Skipping authentication test: no database available")
        return False

    assert db_service is not None
    # mem is required by Authentication init... :-(
    mem.customizer = Customizer()
    mem.configuration = mem.customizer.load_configuration()
    auth = Authentication()

    pwd1 = random_string(8, low=True, up=True, digits=True, symbols=True)
    pwd2 = random_string(8, low=True, up=True, digits=True, symbols=True)

    hash_1 = auth.get_password_hash(pwd1)
    assert len(hash_1) > 0
    assert hash_1 != auth.get_password_hash(pwd2)

    try:
        auth.get_password_hash("")
        pytest.fail('Hashed a empty password!')
    except RestApiException as e:
        assert e.status_code == 401
        assert str(e) == "Invalid password"

    try:
        auth.get_password_hash(None)
        pytest.fail('Hashed a None password!')
    except RestApiException as e:
        assert e.status_code == 401
        assert str(e) == "Invalid password"

    assert auth.verify_password(pwd1, hash_1)
    try:
        auth.verify_password(None, hash_1)
        pytest.fail('Hashed a None password!')
    except TypeError:
        pass

    assert not auth.verify_password(pwd1, None)

    assert not auth.verify_password(None, None)

    ip_data = auth.localize_ip('8.8.8.8')
    assert ip_data is not None
    # I don't know if this tests will be stable...
    assert ip_data == 'United States'

    # import here to prevent loading before initializing things...
    from restapi.services.authentication import BaseAuthentication
    connector = detector.connectors_instances.get('authentication')
    service_instance = connector.custom_init(abackend=db_service)
    assert service_instance.db is not None
    security = HandleSecurity(service_instance)

    user = auth.get_user_object(username=BaseAuthentication.default_user)
    assert user is not None
    # Just to verify that the function works
    assert not security.verify_token(user.email, "doesnotexists")
    assert not security.verify_token(
        user.email,
        "doesnotexists",
        token_type=auth.PWD_RESET
    )
    assert not security.verify_token(
        user.email,
        "doesnotexists",
        token_type=auth.ACTIVATE_ACCOUNT
    )

    t1 = auth.create_temporary_token(user, auth.PWD_RESET)
    assert t1 is not None
    assert isinstance(t1, str)
    assert not security.verify_token(user.email, t1)
    assert not security.verify_token(user.email, t1, token_type=auth.FULL_TOKEN)
    assert security.verify_token(user.email, t1, token_type=auth.PWD_RESET)
    assert not security.verify_token(user.email, t1, token_type=auth.ACTIVATE_ACCOUNT)
    assert not security.verify_token("another@nomail.org", t1)

    # Create another type of temporary token => t1 is still valid
    t2 = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT)
    assert t2 is not None
    assert isinstance(t2, str)
    assert not security.verify_token(user.email, t2)
    assert not security.verify_token(user.email, t2, token_type=auth.FULL_TOKEN)
    assert not security.verify_token(user.email, t2, token_type=auth.PWD_RESET)
    assert security.verify_token(user.email, t2, token_type=auth.ACTIVATE_ACCOUNT)
    assert not security.verify_token("another@nomail.org", t2)

    EXPIRATION = 3
    # Create another token PWD_RESET, this will invalidate t1
    t3 = auth.create_temporary_token(user, auth.PWD_RESET, duration=EXPIRATION)
    assert t3 is not None
    assert isinstance(t3, str)
    assert security.verify_token(user.email, t3, token_type=auth.PWD_RESET)
    assert not security.verify_token(user.email, t1)
    assert not security.verify_token(user.email, t1, token_type=auth.FULL_TOKEN)
    assert not security.verify_token(user.email, t1, token_type=auth.PWD_RESET)
    assert not security.verify_token(user.email, t1, token_type=auth.ACTIVATE_ACCOUNT)

    # Create another token ACTIVATE_ACCOUNT, this will invalidate t2
    t4 = auth.create_temporary_token(user, auth.ACTIVATE_ACCOUNT, duration=EXPIRATION)
    assert t4 is not None
    assert isinstance(t4, str)
    assert security.verify_token(user.email, t4, token_type=auth.ACTIVATE_ACCOUNT)
    assert not security.verify_token(user.email, t2)
    assert not security.verify_token(user.email, t2, token_type=auth.FULL_TOKEN)
    assert not security.verify_token(user.email, t2, token_type=auth.PWD_RESET)
    assert not security.verify_token(user.email, t2, token_type=auth.ACTIVATE_ACCOUNT)

    # token expiration is only 3 seconds... let's test it
    time.sleep(EXPIRATION + 1)
    assert not security.verify_token(user.email, t3, token_type=auth.PWD_RESET)
    assert not security.verify_token(user.email, t4, token_type=auth.ACTIVATE_ACCOUNT)
