# -*- coding: utf-8 -*-

from irods.pool import Pool
from irods.session import iRODSSession

"""

---
WRITE IT

import pickle
from restapi.flask_ext.flask_irods.session import iRODSPickleSession as ips

session = ips(
    user='irods', password='chooseapasswordwisely',
    host='rodserver.dockerized.io', zone='tempZone'
)
# pickle.dumps(session)
with open('test.dat', 'wb') as fh:
    pickle.dump(session, fh)

---

READ IT

import pickle
fh = open('test.dat', 'rb')
session = pickle.load(fh)


"""


class iRODSPickleSession(iRODSSession):

    def __getstate__(self):
        attrs = {}
        for attr in self.__dict__:
            obj = getattr(self, attr)
            if attr == 'pool':
                attrs['account'] = obj.account
            else:
                attrs[attr] = obj

        return attrs

    def __setstate__(self, state):

        for name, value in state.items():
            print(name, value)
            setattr(self, name, value)

        self.pool = Pool(state.get('account'))
