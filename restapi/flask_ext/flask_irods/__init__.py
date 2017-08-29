# -*- coding: utf-8 -*-

"""
iRODS file-system flask connector

============================

# NOTE: the B2ACCESS issue
grid-proxy-init on the certificate creates a valid one...

CERTUSER=13148ea2-4d02-4d2f-b36b-0a646980c779
cd $CERTDIR/$CERTUSER
cp userproxy.crt b2access.proxy.crt
export X509_USER_CERT=$CERTDIR/$CERTUSER/b2access.proxy.crt
export X509_USER_KEY=$CERTDIR/$CERTUSER/b2access.proxy.crt
grid-proxy-init -out userproxy.crt
"""

import os
import logging
from utilities.certificates import Certificates
# from restapi.confs import PRODUCTION
from restapi.flask_ext import BaseExtension, get_logger
from restapi.flask_ext.flask_irods.session \
    import iRODSPickleSession as iRODSSession
# from irods.session import iRODSSession
from restapi.flask_ext.flask_irods.client import IrodsPythonClient

# Silence too much logging from irods
irodslogger = logging.getLogger('irods')
irodslogger.setLevel(logging.INFO)

log = get_logger(__name__)


class IrodsPythonExt(BaseExtension):

    def pre_connection(self, **kwargs):

        session = kwargs.get('user_session')

        if session is not None:
            user = session.email
        else:
            user = kwargs.get('user')
            self.password = kwargs.get('password')

            gss = kwargs.get('gss', False)
            if self.variables.get('external'):
                if self.variables.get('authscheme') == 'GSI':
                    gss = True

            admin = kwargs.get('be_admin', False)
            myproxy_host = self.variables.get("myproxy_host")

            if user is None:
                ##################
                # dockerized iCAT admin bypass
                if not self.variables.get('external') and admin:
                    # Note: 'user' is referring to the main user inside iCAT
                    gss = True
                    user = self.variables.get('default_admin_user')
                ##################
                # external b2safe/irods main user from configuration
                else:
                    # There must be some way to fallback here
                    user = self.variables.get('user')
                    self.password = self.variables.get('password')

        if user is None:
            raise AttributeError("No user is defined")
        else:
            self.user = user
            log.debug("Irods user: %s" % self.user)
            self.schema = self.variables.get('authscheme')

        ######################
        # Irods/b2safe direct credentials
        if session is not None:
            return True
        ######################
        # Identity with GSI
        elif gss:

            Certificates().globus_proxy(
                proxy_file=kwargs.get('proxy_file'),
                user_proxy=self.user,
                cert_dir=self.variables.get("x509_cert_dir"),
                myproxy_host=myproxy_host,
                cert_name=kwargs.get("proxy_cert_name"),
                cert_pwd=kwargs.get("proxy_pass"),
            )

        ######################
        # Normal credentials
        elif self.password is not None:
            self.schema = 'credentials'
        else:
            raise NotImplementedError(
                "Unable to create file-system session: no valid options found")

        return True

    def custom_connection(self, **kwargs):

        check_connection = True
        timeout = kwargs.get('timeout', 15.0)
        session = kwargs.get('user_session')

        if session is not None:
            # recover the serialized session
            obj = self.deserialize(session.session)

        elif self.schema == 'credentials':

            obj = iRODSSession(
                user=self.user,
                password=self.password,
                authentication_scheme='native',
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                zone=self.variables.get('zone'),
            )

        else:

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
                zone=self.variables.get('zone'),
                authentication_scheme=self.variables.get('authscheme'),
                host=self.variables.get('host'),
                port=self.variables.get('port'),
                server_dn=host_dn
            )

            # Do not check for user if its a proxy certificate:
            # we want to verify if they expired later
            if kwargs.get('only_check_proxy', False):
                check_connection = False

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

        # Do a simple command to test this session
        if check_connection:
            u = obj.users.get(self.user)
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
        return super().custom_init()

    def deserialize(self, obj):
        return iRODSSession.deserialize(obj)
