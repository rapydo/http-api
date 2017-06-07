# -*- coding: utf-8 -*-

import os
from functools import lru_cache

from rapydo.utils import htmlcodes as hcodes
from irods.access import iRODSAccess
from irods.models import User, UserGroup, UserAuth
from irods import exception as iexceptions
from rapydo.exceptions import RestApiException

from rapydo.utils.logs import get_logger
log = get_logger(__name__)


class IrodsException(RestApiException):
    pass


class IrodsPythonClient():

    def __init__(self, rpc, variables):
        self.rpc = rpc
        self.variables = variables

    def connect(self):
        return self

    def get_collection_from_path(self, absolute_path):
        return os.path.dirname(absolute_path)

    def get_absolute_path(self, *args, root=None):
        if len(args) < 1:
            return root
        if root is None and not args[0].startswith('/'):
            root = '/'
        return os.path.join(root, *args)

# ##################################
# ##################################
# Re-implemented wrappers
# ##################################
# ##################################
    def is_collection(self, path):
        return self.rpc.collections.exists(path)

    def is_dataobject(self, path):
        try:
            self.rpc.data_objects.get(path)
            return True
        except iexceptions.CollectionDoesNotExist:
            return False
        except iexceptions.DataObjectDoesNotExist:
            return False

    def get_dataobject(self, path):
        try:
            obj = self.rpc.data_objects.get(path)
            return obj
        except (
            iexceptions.CollectionDoesNotExist,
            iexceptions.DataObjectDoesNotExist
        ):
            raise IrodsException("%s not found or no permissions" % path)

    def list(self, path=None, recursive=False, detailed=False, acl=False):
        """ List the files inside an iRODS path/collection """

        if path is None:
            path = self.get_user_home()

        if self.is_dataobject(path):
            raise IrodsException("Cannot list an object, get it instead")
        try:
            data = {}
            root = self.rpc.collections.get(path)

            for coll in root.subcollections:

                row = {}
                key = coll.name
                row["PID"] = None
                row["name"] = coll.name
                row["objects"] = {}
                if recursive:
                    row["objects"] = self.list(
                        coll.path, recursive, detailed, acl)
                row["path"] = coll.path
                row["object_type"] = "collection"
                if detailed:
                    row["owner"] = "-"
                if acl:
                    acl = self.get_permissions(coll)
                    row["acl"] = acl["ACL"]
                    row["acl_inheritance"] = acl["inheritance"]

                data[key] = row

            for obj in root.data_objects:

                row = {}
                key = obj.name
                row["name"] = obj.name
                row["path"] = obj.path
                row["object_type"] = "dataobject"
                row["PID"] = None
                row["checksum"] = None

                if detailed:
                    row["owner"] = obj.owner_name
                    row["content_length"] = obj.size
                    row["created"] = obj.create_time
                    row["last_modified"] = obj.modify_time
                if acl:
                    acl = self.get_permissions(obj)
                    row["acl"] = acl["ACL"]
                    row["acl_inheritance"] = acl["inheritance"]

                data[key] = row

            return data
        except iexceptions.CollectionDoesNotExist as e:
            raise IrodsException("Collection not found: %s" % path)

        # replicas = []
        # for line in lines:
        #     replicas.append(re.split("\s+", line.strip()))
        # return replicas

    def create_empty(self, path, directory=False, ignore_existing=False):

        if directory:
            return self.create_directory(path, ignore_existing)
        else:
            return self.create_file(path, ignore_existing)

    def create_directory(self, path, ignore_existing=False):

        try:

            ret = self.rpc.collections.create(path)
            log.debug("Created irods collection: %s" % path)
            return ret

        except iexceptions.CAT_UNKNOWN_COLLECTION:
            raise IrodsException("Unable to create collection, invalid path")

        except iexceptions.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            if not ignore_existing:
                raise IrodsException(
                    "Irods collection already exists",
                    status_code=hcodes.HTTP_BAD_REQUEST)
            else:
                log.debug("Irods collection already exists: %s" % path)

        except (
            iexceptions.CAT_NO_ACCESS_PERMISSION,
            iexceptions.SYS_NO_API_PRIV
        ):
            raise IrodsException("You have no permissions on path %s" % path)

        return None

    def create_file(self, path, ignore_existing=False):

        try:

            ret = self.rpc.data_objects.create(path)
            log.debug("Create irods object: %s" % path)
            return ret

        except iexceptions.CAT_NO_ACCESS_PERMISSION:
            raise IrodsException("CAT_NO_ACCESS_PERMISSION")

        except iexceptions.SYS_INTERNAL_NULL_INPUT_ERR:
            raise IrodsException("Unable to create object, invalid path")

        except iexceptions.OVERWITE_WITHOUT_FORCE_FLAG:
            if not ignore_existing:
                raise IrodsException(
                    "Irods object already exists",
                    status_code=hcodes.HTTP_BAD_REQUEST)
            log.debug("Irods object already exists: %s" % path)

        return False

    def copy(self, sourcepath, destpath,
             recursive=False, force=False,
             compute_checksum=False, compute_and_verify_checksum=False):

        if self.is_collection(sourcepath):
            raise IrodsException("Copy directory not supported")

        if compute_checksum:
            raise IrodsException(
                "Compute_checksum not supported in copy")

        if compute_and_verify_checksum:
            raise IrodsException(
                "Compute_and_verify_checksum not supported in copy")

        if sourcepath == destpath:
            raise IrodsException(
                "Source and destination path are the same")
        try:
            log.verbose("Copy %s into %s" % (sourcepath, destpath))
            source = self.rpc.data_objects.get(sourcepath)
            self.create_empty(
                destpath, directory=False, ignore_existing=force)
            target = self.rpc.data_objects.get(destpath)
            with source.open('r+') as f:
                with target.open('w') as t:
                    for line in f:
                        # if t.writable():
                        t.write(line)
        except iexceptions.DataObjectDoesNotExist:
            raise IrodsException("Data object not found: %s" % sourcepath)
        except iexceptions.CollectionDoesNotExist:
            raise IrodsException("Collection not found: %s" % sourcepath)

    def move(self, src_path, dest_path):

        try:
            if self.is_collection(src_path):
                self.rpc.collections.move(src_path, dest_path)
                log.debug(
                    "Renamed collection: %s->%s" % (src_path, dest_path))
            else:
                self.rpc.data_objects.move(src_path, dest_path)
                log.debug(
                    "Renamed irods object: %s->%s" % (src_path, dest_path))
        except iexceptions.CAT_RECURSIVE_MOVE:
            raise IrodsException("Source and destination path are the same")
        except iexceptions.SAME_SRC_DEST_PATHS_ERR:
            raise IrodsException("Source and destination path are the same")
        except iexceptions.CAT_NAME_EXISTS_AS_DATAOBJ:
            # raised from both collection and data objects?
            raise IrodsException("Destination path already exists")

    def remove(self, path, recursive=False, force=False, resource=None):
        try:
            if self.is_collection(path):
                self.rpc.collections.remove(
                    path, recurse=recursive, force=force)
                log.debug("Removed irods collection: %s" % path)
            else:
                self.rpc.data_objects.unlink(path, force=force)
                log.debug("Removed irods object: %s" % path)
        except iexceptions.CAT_COLLECTION_NOT_EMPTY:
            raise IrodsException(
                "Cannot delete an empty directory without recursive flag")
        except iexceptions.CAT_NO_ROWS_FOUND:
            raise IrodsException("Irods delete error: path not found")

        # TOFIX: remove resource
        # if resource is not None:
        #     com = 'itrim'
        #     args = ['-S', resource]

        # Try with:
        # self.rpc.resources.remove(name, test=dryRunTrueOrFalse)

    def write_file_content(self, path, content, position=0):
        try:
            obj = self.rpc.data_objects.get(path)
            with obj.open('w+') as handle:

                if position > 0 and handle.seekable():
                    handle.seek(position)

                if handle.writable():

                    # handle.write('foo\nbar\n')
                    a_buffer = bytearray()
                    a_buffer.extend(map(ord, content))
                    handle.write(a_buffer)
                handle.close()
        except iexceptions.DataObjectDoesNotExist:
            raise IrodsException("Cannot write to file: not found")

    def get_file_content(self, path):
        try:
            data = []
            obj = self.rpc.data_objects.get(path)
            with obj.open('r+') as handle:

                if handle.readable():

                    for line in handle:
                        s = line.decode("utf-8")
                        data.append(s)

            return data
        except iexceptions.DataObjectDoesNotExist:
            raise IrodsException("Cannot read file: not found")

    def open(self, absolute_path, destination):

        try:
            obj = self.rpc.data_objects.get(absolute_path)

            # TODO: could use io package?
            with obj.open('r') as handle:
                with open(destination, "wb") as target:
                    for line in handle:
                        target.write(line)
            return True

        except iexceptions.DataObjectDoesNotExist:
            raise IrodsException("Cannot read file: not found")
        return False

    def save(self, path, destination, force=False, resource=None):

        # TOFIX: resource is not used!
        log.warning("Resource not used in saving irods data...")

        try:
            with open(path, "rb") as handle:

                self.create_empty(
                    destination, directory=False, ignore_existing=force)

                obj = self.rpc.data_objects.get(destination)

                try:
                    with obj.open('w') as target:
                        for line in handle:
                            target.write(line)
                except BaseException as e:
                    self.remove(destination, force=True)
                    raise e

            return True

        except iexceptions.CollectionDoesNotExist:
            raise IrodsException("Cannot write to file: path not found")
        # except iexceptions.DataObjectDoesNotExist:
        #     raise IrodsException("Cannot write to file: not found")

        return False

    ############################################
    # ############ ACL Management ##############
    ############################################

    def get_permissions(self, coll_or_obj):

        if type(coll_or_obj) is str:

            if self.is_collection(coll_or_obj):
                coll_or_obj = self.rpc.collections.get(coll_or_obj)
            elif self.is_dataobject(coll_or_obj):
                coll_or_obj = self.rpc.collections.get(coll_or_obj)
            else:
                coll_or_obj = None

        if coll_or_obj is None:
            raise IrodsException("Cannot get permission of a null object")

        data = {}
        data["path"] = coll_or_obj.path
        data["ACL"] = []
        acl_list = self.rpc.permissions.get(coll_or_obj)

        for acl in acl_list:
            data["ACL"].append([
                acl.user_name,
                acl.user_zone,
                acl.access_name
            ])

        # TOFIX: how to retrieve inheritance?
        data["inheritance"] = "N/A"

        return data

    def set_permissions(self, path, permission, userOrGroup,
                        zone='', recursive=False):

        try:

            ACL = iRODSAccess(
                access_name=permission,
                path=path,
                user_name=userOrGroup,
                user_zone=zone)
            self.rpc.permissions.set(ACL, recursive=recursive)

            log.debug(
                "Set %s permission to %s for %s" %
                (permission, path, userOrGroup))
            return True

        except iexceptions.CAT_INVALID_USER:
            raise IrodsException("Cannot set ACL: user or group not found")
        except iexceptions.CAT_INVALID_ARGUMENT:
            if not self.is_collection(path) and not self.is_dataobject(path):
                raise IrodsException("Cannot set ACL: path not found")
            else:
                raise IrodsException("Cannot set ACL")

        return False

    def set_inheritance(self, path, inheritance=True, recursive=False):

        try:
            if inheritance:
                permission = "inherit"
            else:
                permission = "noinherit"

            ACL = iRODSAccess(
                access_name=permission,
                path=path,
                user_name='',
                user_zone='')
            self.rpc.permissions.set(ACL, recursive=recursive)
            log.debug("Set inheritance %r to %s" % (inheritance, path))
            return True
        except iexceptions.CAT_NO_ACCESS_PERMISSION:
            if self.is_dataobject(path):
                raise IrodsException("Cannot set inheritance to a data object")
            else:
                raise IrodsException(
                    "Cannot set inheritance: collection not found")
        return False

    def get_user_home(self, user=None):

        zone = self.get_current_zone(prepend_slash=True)

        if user is None:
            user = self.get_current_user()

        home = self.variables.get('home', 'home')
        if home.startswith(zone):
            home = home[len(zone):]

        path = os.path.join(zone, home.lstrip('/'), user)
        return path

        # if user == self.variables.get('user'):
        #     home = self.variables.get('home')
        # else:
        #     home = os.path.join('home', user)

        # if home.startswith("/"):
        #     if home.startswith(zone):
        #         home = home[len(zone):]
        #     else:
        #         home = home[1:]

        # path = os.path.join(zone, home.lstrip('/'))
        # return path

    def get_current_user(self):
        return self.rpc.username

    def get_current_zone(self, prepend_slash=False):
        zone = self.rpc.zone
        if prepend_slash:
            zone = '/' + zone
        return zone

    @lru_cache(maxsize=4)
    def get_user_info(self, username=None):

        if username is None:
            username = self.get_current_user()
        try:
            user = self.rpc.users.get(username)
            data = {}
            data["id"] = user.id
            data["name"] = user.name
            data["type"] = user.type
            data["zone"] = user.zone
            # data["info"] = ""
            # data["comment"] = ""
            # data["create time"] = ""
            # data["modify time"] = ""
            data["account"] = user.manager.sess.pool.account.__dict__

            results = self.rpc.query(UserGroup.name).filter(
                User.name == user.name).get_results()
            groups = []
            for obj in results:
                for _, grp in obj.items():
                    groups.append(grp)

            data['groups'] = groups
            return data
        except iexceptions.UserDoesNotExist:
            return None

    def user_has_group(self, username, groupname):
        info = self.get_user_info(username)
        if info is None:
            return False
        if 'groups' not in info:
            return False
        return groupname in info['groups']

# TODO: merge the two following 'user_exists'
    def check_user_exists(self, username, checkGroup=None):
        userdata = self.get_user_info(username)
        if userdata is None:
            return False, "User %s does not exist" % username
        if checkGroup is not None:
            if checkGroup not in userdata['groups']:
                return False, "User %s is not in group %s" %\
                    (username, checkGroup)
        return True, "OK"

    def query_user_exists(self, user):
        results = self.rpc.query(User.name).filter(User.name == user).first()

        if results is None:
            return False
        elif results[User.name] == user:
            return True
        else:
            raise AttributeError("Failed to query")

    def get_metadata(self, path):

        try:
            obj = self.rpc.data_objects.get(path)

            data = {}
            units = {}
            for meta in obj.metadata.items():

                name = meta.name

                data[name] = meta.value
                units[name] = meta.units

            return data, units
        except (
            iexceptions.CollectionDoesNotExist,
            iexceptions.DataObjectDoesNotExist
        ):
            raise IrodsException("Cannot extract metadata, object not found")

    # We may need this for testing the get_metadata
    def set_metadata(self, path, **meta):
        try:
            obj = self.rpc.data_objects.get(path)
            for key, value in meta.items():
                obj.metadata.add(key, value)
        except iexceptions.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            raise IrodsException("This metadata already exist")
        except iexceptions.DataObjectDoesNotExist:
            raise IrodsException("Cannot set metadata, object not found")

    def get_user_from_dn(self, dn):
        results = self.rpc.query(User.name, UserAuth.user_dn) \
            .filter(UserAuth.user_dn == dn).first()
        if results is not None:
            return results.get(User.name)
        else:
            return None

    def create_user(self, user, admin=False):

        if user is None:
            log.error("Asking for NULL user...")
            return False

        user_type = 'rodsuser'
        if admin:
            user_type = 'rodsadmin'

        try:
            user_data = self.rpc.users.create(user, user_type)
            log.debug("Created user %s" % user_data)
        except iexceptions.CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME:
            log.warning("User %s already exists in iRODS" % user)
            return False

        return True

    def list_user_attributes(self, user):

        try:
            data = self.rpc.query(
                User.id, User.name, User.type, User.zone
            ).filter(User.name == user).one()
        except iexceptions.NoResultFound:
            return None

        try:
            auth_data = self.rpc.query(
                UserAuth.user_dn
            ).filter(UserAuth.user_id == data[User.id]).one()
            dn = auth_data.get(UserAuth.user_dn)
        except iexceptions.NoResultFound:
            dn = None

        return {
            'name': data[User.name],
            'type': data[User.type],
            'zone': data[User.zone],
            'dn': dn
        }

    def modify_user_dn(self, user, dn, zone):

        # addAuth / rmAuth
        self.rpc.users.modify(user, 'addAuth', dn)
        # self.rpc.users.modify(user, 'addAuth', dn, user_zone=zone)


# ####################################################
# ####################################################
# ####################################################
    # FROM old client.py:
# ####################################################
# ####################################################
# ####################################################

#     def query_icat(self, query, key):
#         com = 'iquest'
#         args = ["%s" % query]
#         output = self.basic_icom(com, args)
#         log.debug("%s query: [%s]\n%s" % (com, query, output))
#         if 'CAT_NO_ROWS_FOUND' in output:
#             return None
#         return output.split('\n')[0].lstrip("%s = " % key)

#     def query_user(self, select="USER_NAME", where="USER_NAME", field=None):
#         query = "SELECT %s WHERE %s = '%s'" % (select, where, field)
#         return self.query_icat(query, select)

#     def get_base_dir(self):
#         com = "ipwd"
#         iout = self.basic_icom(com).strip()
#         log.very_verbose("Base dir is %s" % iout)
#         return iout

#     ############################################
#     # ######### Resources Management ###########
#     ############################################

#     # for resources use this object manager:
#     # self.rpc.resources
#     def list_resources(self):
#         com = 'ilsresc'
#         iout = self.basic_icom(com).strip()
#         log.debug("Resources %s" % iout)
#         return iout.split("\n")

#     def get_base_resource(self):
#         resources = self.list_resources()
#         if len(resources) > 0:
#             return resources[0]
#         return None

#     def get_resources_from_file(self, filepath):
#         output = self.list(path=filepath, detailed=True)
#         resources = []
#         for elements in output:
#             # elements = line.split()
#             if len(elements) < 3:
#                 continue
#             resources.append(elements[2])

#         log.debug("%s: found resources %s" % (filepath, resources))
#         return resources

#     def admin(self, command, user=None, extra=None):
#         """
#         Admin commands to manage users and stuff like that.
#         Note: it will give irods errors if current user has not privileges.
#         """

#         com = 'iadmin'
#         args = [command]
#         if user is not None:
#             args.append(user)
#         if extra is not None:
#             args.append(extra)
#         log.debug("iRODS admininistration command '%s'" % command)
#         return self.basic_icom(com, args)

#     def admin_list(self):
#         """
#         How to explore collections in a debug way
#         """
#         return self.admin('ls')

# # FIXME:
#     def get_current_user_environment(self):
#         com = 'ienv'
#         output = self.basic_icom(com)
#         print("ENV IS", output)
#         return output

#     def current_location(self, ifile):
#         """
#         irods://130.186.13.14:1247/cinecaDMPZone/home/pdonorio/replica/test2
#         """
#         protocol = 'irods'
#         URL = "%s://%s:%s%s" % (
#             protocol,
#             self._current_environment['IRODS_HOST'],
#             self._current_environment['IRODS_PORT'],
#             os.path.join(self._base_dir, ifile))
#         return URL

#     def get_resource_from_dataobject(self, ifile):
#         """ The attribute of resource from a data object """
#         details = self.list(ifile, True)
#         resources = []
#         for element in details:
#             # 2nd position is the resource in irods ils -l
#             resources.append(element[2])
#         return resources

#     def get_resources_admin(self):
#         resources = []
#         out = self.admin(command='lr')
#         if isinstance(out, str):
#             resources = out.strip().split('\n')
#         return resources

#     def get_default_resource_admin(self, skip=['bundleResc']):
#         # TOFIX: find out the right way to get the default irods resource

#         # note: we could use ienv
#         resources = self.get_resources_admin()
#         if len(resources) > 0:
#             # Remove strange resources
#             for element in skip:
#                 if element in resources:
#                     resources.pop(resources.index(element))
#             return list(resources)[::-1].pop()
#         return None

#     def handle_collection_path(self, ipath):
#         """
#             iRODS specific pattern to handle paths
#         """

#         home = self.get_base_dir()

#         # Should add the base dir if doesn't start with /
#         if ipath is None or ipath == '':
#             ipath = home
#         elif ipath[0] != '/':
#             ipath = home + '/' + ipath
#         else:
#             current_zone = self.get_current_zone()
#             if not ipath.startswith('/' + current_zone):
#                 # Add the zone
#                 ipath = '/' + current_zone + ipath

#         # Append / if missing in the end
#         if ipath[-1] != '/':
#             ipath += '/'

#         return ipath

#     def get_irods_path(self, collection, filename=None):

#         path = self.handle_collection_path(collection)
#         if filename is not None:
#             path += filename
#         return path

#     # def get_default_user(self):
#     #     return IRODS_DEFAULT_USER

#     def translate_graph_user(self, graph, graph_user):
#         from rapydo.services.irods.translations import Irods2Graph
#         return Irods2Graph(graph, self).graphuser2irodsuser(graph_user)

# ################################################
# ################################################
# #  NEED TO CHECK ALL OF THIS ICOMMANDS BELOW
# ################################################
# ################################################

#     def search(self, path, like=True):
#         com = "ilocate"
#         if like:
#             path += '%'
#         log.debug("iRODS search for %s" % path)
#         # Execute
#         out = self.execute_command(com, path)
#         content = out.strip().split('\n')
#         print("TEST", content)
#         return content

#     def replica(self, dataobj, replicas_num=1, resOri=None, resDest=None):
#         """ Replica
#         Replicate a file in iRODS to another storage resource.
#         Note that replication is always within a zone.
#         """

#         com = "irepl"
#         if resOri is None:
#             resOri = self.first_resource
#         if resDest is None:
#             resDest = self.second_resource

#         args = [dataobj]
#         args.append("-P")  # debug copy
#         args.append("-n")
#         args.append(replicas_num)
#         # Ori
#         args.append("-S")
#         args.append(resOri)
#         # Dest
#         args.append("-R")
#         args.append(resDest)

#         return self.basic_icom(com, args)

#     def replica_list(self, dataobj):
#         return self.get_resource_from_dataobject(dataobj)
