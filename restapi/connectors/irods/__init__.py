"""
iRODS file-system flask connector
"""

# import os
import logging

# from irods.session import iRODSSession
from irods import exception as iexceptions

# from restapi.confs import PRODUCTION
from restapi.utilities.logs import log
from restapi.connectors import Connector
from restapi.connectors.irods.session import iRODSPickleSession as iRODSSession
from restapi.connectors.irods.client import IrodsException, IrodsPythonClient
from restapi.connectors.irods.certificates import Certificates

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
        return None

    def preconnect(self, **kwargs):

        session = kwargs.get('user_session')

        external = self.variables.get('external')

        # Retrieve authentication schema
        self.authscheme = kwargs.get('authscheme')
        # Authentication scheme fallback to default from project_configuration
        if self.authscheme is None or self.authscheme.strip() == '':
            self.authscheme = self.variables.get('authscheme')
        # Authentication scheme fallback to default (credentials)
        if self.authscheme is None or self.authscheme.strip() == '':
            self.authscheme = NORMAL_AUTH_SCHEME

        if session is not None:
            user = session.email
        else:
            user = kwargs.get('user')
            self.password = kwargs.get('password')

            gss = kwargs.get('gss', False)
            myproxy_host = self.variables.get("myproxy_host")

            admin = kwargs.get('be_admin', False)
            if user is None:
                user_key = 'default_admin_user' if admin else 'user'
                user = self.variables.get(user_key)

            if self.password is None:
                if self.authscheme == NORMAL_AUTH_SCHEME:
                    self.password = self.variables.get('password')
                # No tests provided for PAM and GSI
                elif self.authscheme == PAM_AUTH_SCHEME:  # pragma: no cover
                    self.password = self.variables.get('password')

            # Check if the user requested for GSI explicitely

            # No tests provided for PAM and GSI
            if self.authscheme == GSI_AUTH_SCHEME:  # pragma: no cover
                gss = True

        if user is None:
            raise AttributeError("No user is defined")
        else:
            self.user = user
            log.debug("Irods user: {}", self.user)

        ######################
        # Irods/b2safe direct credentials
        if session is not None:
            return True
        ######################
        # Identity with GSI
        # No tests provided for PAM and GSI
        elif gss:  # pragma: no cover

            if self.authscheme != GSI_AUTH_SCHEME:
                log.debug("Forcing {} authscheme", GSI_AUTH_SCHEME)
                self.authscheme = GSI_AUTH_SCHEME

            pref = self.variables.get('certificates_prefix', "")
            name = kwargs.get("proxy_cert_name")
            proxy_cert_name = f"{pref}{name}"

            valid_cert = Certificates.globus_proxy(
                proxy_file=kwargs.get('proxy_file'),
                user_proxy=self.user,
                cert_dir=self.variables.get("x509_cert_dir"),
                myproxy_host=myproxy_host,
                cert_name=proxy_cert_name,
                cert_pwd=kwargs.get("proxy_pass"),
            )

            if not valid_cert:
                return False

        # No tests provided for PAM and GSI
        elif self.authscheme == PAM_AUTH_SCHEME:  # pragma: no cover
            pass

        elif self.password is not None:
            self.authscheme = NORMAL_AUTH_SCHEME

        else:
            raise NotImplementedError(
                "Unable to create session: invalid iRODS-auth scheme"
            )

        return True

    def postconnect(self, obj, **kwargs):
        return True

    def connect(self, **kwargs):

        check_connection = True
        timeout = kwargs.get('timeout', 15.0)
        session = kwargs.get('user_session')
        default_zone = self.variables.get('zone')

        if session is not None:
            # recover the serialized session
            obj = self.deserialize(session.session)

        elif self.authscheme == NORMAL_AUTH_SCHEME:

            obj = iRODSSession(
                user=self.user,
                password=self.password,
                authentication_scheme='native',
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                zone=default_zone,
            )

        # No tests provided for PAM and GSI
        elif self.authscheme == GSI_AUTH_SCHEME:  # pragma: no cover

            # Server host certificate
            # In case not set, recover from the shared dockerized certificates
            host_dn = self.variables.get('dn', None)
            if isinstance(host_dn, str) and host_dn.strip() == '':
                host_dn = None
            if host_dn is None:
                host_dn = Certificates.get_dn_from_cert(
                    certdir='host', certfilename='hostcert'
                )
            else:
                log.verbose("Existing DN:\n\"{}\"", host_dn)

            obj = iRODSSession(
                user=self.user,
                authentication_scheme=self.authscheme,
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                server_dn=host_dn,
                zone=default_zone,
            )

            # Do not check for user if its a proxy certificate:
            # we want to verify if they expired later
            if kwargs.get('only_check_proxy', False):
                check_connection = False

        # No tests provided for PAM and GSI
        elif self.authscheme == PAM_AUTH_SCHEME:  # pragma: no cover

            obj = iRODSSession(
                user=self.user,
                password=self.password,
                authentication_scheme=self.authscheme,
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                zone=default_zone,
            )

        else:  # pragma: no cover
            raise NotImplementedError(
                f"Invalid iRODS authentication scheme: {self.authscheme}"
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
        obj.connection_timeout = timeout

        #########################
        # TODO: this connection test, like in restapi wait
        # should be used for debugging, with the output in case of failure
        # restapi verify SERVICE
        #########################

        # Back-compatibility fix, remove-me after the prc PR
        try:
            PAM_EXCEPTION = iexceptions.PAM_AUTH_PASSWORD_FAILED
        except AttributeError:
            # An exception that should never occur since already tested
            PAM_EXCEPTION = iexceptions.CAT_INVALID_AUTHENTICATION

        # Do a simple command to test this session
        if check_connection:
            catch_exceptions = kwargs.get('catch_exceptions', False)
            try:
                u = obj.users.get(self.user, user_zone=default_zone)

            except iexceptions.CAT_INVALID_AUTHENTICATION as e:
                if catch_exceptions:
                    raise IrodsException("CAT_INVALID_AUTHENTICATION")
                else:
                    raise e

            # except iexceptions.PAM_AUTH_PASSWORD_FAILED as e:
            except PAM_EXCEPTION as e:
                if catch_exceptions:
                    raise IrodsException("PAM_AUTH_PASSWORD_FAILED")
                else:
                    raise e

            log.verbose("Tested session retrieving '{}'", u.name)

        client = IrodsPythonClient(prc=obj, variables=self.variables)
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
