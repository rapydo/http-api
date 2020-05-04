# -*- coding: utf-8 -*-
import os
import random
import string
import pytest
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


def test_authentication():

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
