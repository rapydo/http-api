from restapi.utilities.processes import find_process
# from restapi.utilities.processes import wait_socket
from restapi.utilities.meta import Meta
from restapi.utilities.logs import handle_log_output, obfuscate_dict

def test_libs():

    assert not find_process("this-should-not-exist")
    s = Meta.get_submodules_from_package(None)
    assert isinstance(s, list)
    assert len(s) == 0

    s = handle_log_output(None)
    assert isinstance(s, dict)
    assert len(s) == 0

    s = handle_log_output(" ")
    assert isinstance(s, dict)
    assert len(s) == 0

    # obfuscate_dict only accepts dict
    assert obfuscate_dict(None) is None
    assert obfuscate_dict(10) == 10
    assert obfuscate_dict(['x']) == ['x']
    assert len(obfuscate_dict({})) == 0
    assert obfuscate_dict({"x": "y"}) == {"x": "y"}
    assert obfuscate_dict({"password": "y"}) == {"password": "****"}
    assert obfuscate_dict({"pwd": "y"}) == {"pwd": "****"}
    assert obfuscate_dict({"token": "y"}) == {"token": "****"}
    assert obfuscate_dict({"access_token": "y"}) == {"access_token": "****"}
    assert obfuscate_dict({"file": "y"}) == {"file": "****"}
    assert obfuscate_dict({"filename": "y"}) == {"filename": "****"}
    assert obfuscate_dict({"new_password": "y"}) == {"new_password": "****"}
    assert obfuscate_dict({"password_confirm": "y"}) == {"password_confirm": "****"}
