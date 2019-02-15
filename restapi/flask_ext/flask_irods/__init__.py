# -*- coding: utf-8 -*-

"""
iRODS file-system flask connector
"""

# import os
import logging
from utilities.certificates import Certificates
# from restapi.confs import PRODUCTION
from restapi.flask_ext import BaseExtension, get_logger
from restapi.flask_ext.flask_irods.session \
    import iRODSPickleSession as iRODSSession
# from irods.session import iRODSSession
from irods import exception as iexceptions
from restapi.flask_ext.flask_irods.client \
    import IrodsException, IrodsPythonClient

# Silence too much logging from irods
irodslogger = logging.getLogger('irods')
irodslogger.setLevel(logging.INFO)

NORMAL_AUTH_SCHEME = 'credentials'
GSI_AUTH_SCHEME = 'GSI'
PAM_AUTH_SCHEME = 'PAM'

log = get_logger(__name__)


class IrodsPythonExt(BaseExtension):

    def pre_connection(self, **kwargs):

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
                if admin:
                    user = self.variables.get('default_admin_user')
                    self.authscheme = GSI_AUTH_SCHEME
                else:
                    user = self.variables.get('user')
                    if self.authscheme == NORMAL_AUTH_SCHEME:
                        self.password = self.variables.get('password')
                    elif self.authscheme == PAM_AUTH_SCHEME:
                        self.password = self.variables.get('password')

            log.very_verbose(
                "Check connection parameters:" +
                "\nexternal[%s], auth[%s], user[%s], admin[%s]",
                external, self.authscheme, user, admin
            )

            # Check if the user requested for GSI explicitely
            if self.authscheme == GSI_AUTH_SCHEME:
                # if self.variables.get('external'):
                gss = True

        if user is None:
            raise AttributeError("No user is defined")
        else:
            self.user = user
            log.debug("Irods user: %s", self.user)

        ######################
        # Irods/b2safe direct credentials
        if session is not None:
            return True
        ######################
        # Identity with GSI
        elif gss:

            if self.authscheme != GSI_AUTH_SCHEME:
                log.debug("Forcing %s authscheme" % GSI_AUTH_SCHEME)
                self.authscheme = GSI_AUTH_SCHEME

            proxy_cert_name = "%s%s" % (
                self.variables.get('certificates_prefix', ""),
                kwargs.get("proxy_cert_name")
            )

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

        elif self.authscheme == PAM_AUTH_SCHEME:
            pass

        elif self.password is not None:
            self.authscheme = NORMAL_AUTH_SCHEME

        else:
            raise NotImplementedError(
                "Unable to create session: invalid iRODS-auth scheme")
        # log.pp(self.variables)

        return True

    def custom_connection(self, **kwargs):

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

        elif self.authscheme == GSI_AUTH_SCHEME:

            # Server host certificate
            # In case not set, recover from the shared dockerized certificates
            host_dn = self.variables.get('dn', None)
            if isinstance(host_dn, str) and host_dn.strip() == '':
                host_dn = None
            if host_dn is None:
                host_dn = Certificates.get_dn_from_cert(
                    certdir='host', certfilename='hostcert')
            else:
                log.verbose("Existing DN:\n\"%s\"" % host_dn)

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

        elif self.authscheme == PAM_AUTH_SCHEME:

            obj = iRODSSession(
                user=self.user,
                password=self.password,
                authentication_scheme=self.authscheme,
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                zone=default_zone,
            )

        else:
            raise NotImplementedError(
                "Invalid iRODS authentication scheme: %s" % self.authscheme)

        # # set timeout on existing socket/connection
        # with obj.pool.get_connection() as conn:
        #     timer = conn.socket.gettimeout()
        #     log.debug("Current timeout: %s" % timer)
        #     conn.socket.settimeout(10.0)
        #     timer = conn.socket.gettimeout()
        #     log.debug("New timeout: %s" % timer)

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

            log.verbose("Tested session retrieving '%s'" % u.name)

        client = IrodsPythonClient(prc=obj, variables=self.variables)
        return client

    def custom_init(self, pinit=False, **kwargs):
        # NOTE: we ignore args here

        # if pinit and not self.variables.get('external'):
        #     log.debug("waiting for internal certificates")
        #     # should actually connect with user and password
        #     # and verify if GSI is already registered with admin rodsminer
        #     import time
        #     time.sleep(5)

        # recover instance with the parent method
        session = super().custom_init()

        # IF variable 'IRODS_ANONYMOUS? is set THEN
        # Check if external iRODS / B2SAFE has the 'anonymous' user available
        user = 'anonymous'
        if self.variables.get('external') and self.variables.get(user):
            if not session.query_user_exists(user):
                log.exit(
                    "Cannot find '%s' inside " +
                    "the currently connected iRODS instance", user)

        return session

    def deserialize(self, obj):
        return iRODSSession.deserialize(obj)
