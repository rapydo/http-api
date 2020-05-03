# -*- coding: utf-8 -*-
import os
import random
import string
from restapi.connectors.authentication import HandleSecurity
from restapi.services.detect import detector
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
        log.warning("Skipping authentication test: service not avaiable")
        return False

    auth = detector.connectors_instances.get('authentication').get_instance()
    security = HandleSecurity(auth)

    min_pwd_len = int(os.environ.get("AUTH_MIN_PASSWORD_LENGTH", 9999))

    pwd = random_string(min_pwd_len - 1)
    ret_val, ret_text = security.verify_password_strength(pwd, old_pwd=pwd)
    assert not ret_val
    assert ret_text == 'The new password cannot match the previous password'

    pwd = random_string(min_pwd_len - 1)
    ret_val, ret_text = security.verify_password_strength(pwd, old_pwd='anotherpwd')
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
