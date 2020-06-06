"""
iRODS file-system flask connector
"""

# import os
import logging

# from irods.session import iRODSSession
from irods import exception as iexceptions
from gssapi.raw import GSSError

# from restapi.confs import PRODUCTION
from restapi.utilities.logs import log
from restapi.connectors import Connector
from restapi.env import Env
from restapi.connectors.irods.session import iRODSPickleSession as iRODSSession
from restapi.connectors.irods.client import IrodsPythonClient
from restapi.connectors.irods.certificates import Certificates
from restapi.exceptions import ServiceUnavailable

# Silence too much logging from irods
irodslogger = logging.getLogger('irods')
irodslogger.setLevel(logging.INFO)

NORMAL_AUTH_SCHEME = 'credentials'
GSI_AUTH_SCHEME = 'GSI'
PAM_AUTH_SCHEME = 'PAM'


# Excluded from coverage because it is only used by a very specific service
# No further tests will be included in the core
class IrodsPythonExt(Connector):

    def get_connection_exception(self):
        return (
            NotImplementedError,
            ServiceUnavailable,
            AttributeError,
            GSSError,
            FileNotFoundError,
        )

    def connect(self, **kwargs):

        variables = self.variables.copy()
        variables.update(kwargs)

        session = variables.get('user_session')

        authscheme = variables.get('authscheme', NORMAL_AUTH_SCHEME)

        if session:
            user = session.email
        else:

            admin = variables.get('be_admin', False)
            user_key = 'default_admin_user' if admin else 'user'
            user = variables.get(user_key)
            password = variables.get('password')

        if user is None:
            raise AttributeError("No user is defined")
        log.debug("Irods user: {}", user)

        ######################
        if session:
            # recover the serialized session
            obj = self.deserialize(session.session)

        elif authscheme == GSI_AUTH_SCHEME:

            cert_pref = variables.get('certificates_prefix', "")
            cert_name = variables.get("proxy_cert_name")

            valid_cert = Certificates.globus_proxy(
                proxy_file=variables.get('proxy_file'),
                user_proxy=user,
                cert_dir=variables.get("x509_cert_dir"),
                myproxy_host=variables.get("myproxy_host"),
                cert_name=f"{cert_pref}{cert_name}",
                cert_pwd=variables.get("proxy_pass"),
            )

            if not valid_cert:
                raise ServiceUnavailable("Invalid proxy settings")

            # Server host certificate
            # In case not set, recover from the shared dockerized certificates
            if host_dn := variables.get('dn', None):
                log.verbose("Existing DN:\n\"{}\"", host_dn)
            else:
                host_dn = Certificates.get_dn_from_cert(
                    certdir='host', certfilename='hostcert'
                )

            obj = iRODSSession(
                user=user,
                authentication_scheme=authscheme,
                host=variables.get('host'),
                port=variables.get('port'),
                server_dn=host_dn,
                zone=variables.get('zone'),
            )

        elif authscheme == PAM_AUTH_SCHEME:

            obj = iRODSSession(
                user=user,
                password=password,
                authentication_scheme=authscheme,
                host=variables.get('host'),
                port=variables.get('port'),
                zone=variables.get('zone'),
            )

        elif password is not None:
            authscheme = NORMAL_AUTH_SCHEME

            obj = iRODSSession(
                user=user,
                password=password,
                authentication_scheme='native',
                host=variables.get('host'),
                port=variables.get('port'),
                zone=variables.get('zone'),
            )

        else:
            raise NotImplementedError(
                f"Invalid iRODS authentication scheme: {authscheme}"
            )

        # # set timeout on existing socket/connection
        # with obj.pool.get_connection() as conn:
        #     timer = conn.socket.gettimeout()
        #     log.debug("Current timeout: {}", timer)
        #     conn.socket.settimeout(10.0)
        #     timer = conn.socket.gettimeout()
        #     log.debug("New timeout: {}", timer)

        # based on https://github.com/irods/python-irodsclient/pull/90
        # NOTE: timeout has to be below 30s (http request timeout)
        obj.connection_timeout = Env.to_int(variables.get('timeout'), 15.0)

        # Do a simple command to test this session
        if not Env.to_bool(variables.get('only_check_proxy')):
            try:
                u = obj.users.get(
                    user,
                    user_zone=variables.get('zone')
                )

            except iexceptions.CAT_INVALID_AUTHENTICATION as e:
                raise e

            # except iexceptions.PAM_AUTH_PASSWORD_FAILED as e:
            except iexceptions.PAM_AUTH_PASSWORD_FAILED as e:
                raise e

            log.verbose("Tested session retrieving '{}'", u.name)

        client = IrodsPythonClient(prc=obj, variables=variables)
        return client

    # initialize is only invoked for backend databases
    def initialize(self):  # pragma: no cover
        pass

    # destroy is only invoked for backend databases
    def destroy(self):  # pragma: no cover
        pass

    @staticmethod
    def deserialize(obj):
        return iRODSSession.deserialize(obj)
