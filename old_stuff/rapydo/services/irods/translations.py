# -*- coding: utf-8 -*-

""" Converting irods data into GraphDB models """

import os

# TOFIX: should we move this import?
from py2neo.error import GraphError
from py2neo.cypher.error.schema import ConstraintViolation
from neomodel.exception import RequiredProperty
from neomodel.exception import UniqueProperty

from rapydo.utils.logs import get_logger
log = get_logger(__name__)


class AccountsToIrodsUsers(object):

    @staticmethod
    def email2iuser(username):
        """
        Note: this was a first proposal and is going to become deprecated.

        Get first 8 chars of the first part of email (with no dots)
        """
        return username.split('@')[0].replace('.', '')[:8]


class Irods2Graph(object):

    def __init__(self, graph, icom):
        self._graph = graph
        self._icom = icom

    def collection2node(self, collection, path, current_zone):

        p = path.lstrip('/').lstrip(current_zone.name)
        properties = {
            # remove the zone from collection path
            'path': p,
            'name': collection,
        }

        current_collection = None
        try:
            current_collection = self._graph.Collection(**properties).save()
        except (GraphError, RequiredProperty,
                UniqueProperty, ConstraintViolation):
            current_collection = \
                list(self._graph.Collection.nodes.filter(path=p)).pop()

        return current_collection

    def recursive_collection2node(
            self, collections, current_dobj=None, current_zone=None):

        if current_zone is None:
            current_zone = self._graph.Zone.nodes.get(
                name=self._icom.get_current_zone())

        collection_counter = 0
        last_collection = None

        for collection, path in collections:

            collection_counter += 1
            log.debug("Collection %s" % collection)
            current_collection = self.collection2node(
                collection, path, current_zone)

            # Link the first one to dataobject
            if collection_counter == 1 and current_dobj is not None:
                current_dobj.belonging.connect(current_collection)

            # Link to zone
            # if collection_counter == len(collections):
            current_collection.hosted.connect(current_zone)

            # Otherwise connect to the previous?
            if last_collection is not None:
                last_collection.matrioska_to.connect(current_collection)

            last_collection = current_collection

        return last_collection

    def split_ipath(self, ipath, with_file=True):
        """
        Getting the three pieces from Absolute Path of data object:
            zone, absolute path and filename.
        Also keeps track of collections.
        """

        zone = ""
        irods_path = ""
        collections = []
        filename = None

        if with_file:
            (prefix, filename) = os.path.split(ipath)
        else:
            prefix = ipath

        while prefix != "/":
            oripath = prefix
            # Note: THIS IS NOT IRODS_PATH AS EUDAT THINKS OF IT
            irods_path = os.path.join(zone, irods_path)
            # Split into basename and dir
            (prefix, zone) = os.path.split(prefix)
            # Skip the last one, as it is a Zone and not a collection
            if zone != oripath.strip('/') and zone.strip() != '':
                # Save collection name (zone) and its path (prefix+zone)
                collections.append((zone, oripath))

        ##################################
        # Store Zone node
        current_zone = self._graph.Zone.get_or_create({'name': zone}).pop()

        return (filename, collections, current_zone)

    def graphuser2irodsuser(self, graphuser, set_as_current=True):
        users = graphuser.associated.search(default_user=True)
        if len(users) != 1:
            raise AttributeError(
                "No unique default user for %s" % graphuser.name)
        user = users.pop()
        if set_as_current:
            self._icom.change_user(user.username)
        return user

    def ifile2nodes(self, ifile, service_user=None):
        """
TO BE FIXED
        """
        raise NotImplementedError("Fix with new graphdb models")

        filename, collections, current_zone = self.split_ipath(ifile)

        # Eudat URL
        location = self._icom.current_location(ifile)
        log.debug("Location: %s" % location)

        ##################################
        # Store Data Object

        # Prepare properties
        properties = {
            'location': location,
            'filename': filename,
            'path': ifile,
        }
        # Build UUID
        current_dobj = None
        try:
            current_dobj = self._graph.DataObject.nodes.get(location=location)
        except self._graph.DataObject.DoesNotExist:
            current_dobj = self._graph.DataObject(**properties).save()
        # Connect the object
        current_dobj.located.connect(current_zone)
        log.info("Created and connected data object %s" % filename)

        ##################################
        # Connect to irods user
        user = self._icom.get_current_user()
        current_user = None
        try:
## to check: irods user should already exist?
            current_user = list(self._graph.
                                IrodsUser.nodes.filter(username=user)).pop()
        except Exception as e:
            raise AttributeError(
                "Irods user %s does not exist in the graph!\n%s" % (user, e))
        current_dobj.owned.connect(current_user)

        # Connect the irods user to current_token
        if service_user is not None:
            current_user.associated.connect(service_user)

        ##################################
        # # System metadata
        # for key, value in self._icom.meta_sys_list(ifile):

        #     print("key", key, "value", value)
        #     # data = {'metatype':'system', 'key':key, 'value':value}
        #     # save_node_metadata(graph, data, current_dobj)

        #     # People/User
        #     if key == 'data_owner_name':
        #         current_user = self._graph.IrodsUser.get_or_create(
        #             {'username': value}).pop()
        #         current_dobj.owned.connect(current_user)

        ##################################
        # Get Name and Store Resource node
        resources = self._icom.get_resource_from_dataobject(ifile)

        for resource_name in resources:
            log.debug("Resource %s" % resource_name)
            current_resource = \
                self._graph.Resource.get_or_create(
                    {'name': resource_name}).pop()
            # Connect resource to Zone
            current_resource.hosted.connect(current_zone)
            # Connect data object to this replica resource
            current_dobj.stored.connect(current_resource)

        ##################################
        # Store Collections

        self.recursive_collection2node(
            collections, current_zone=current_zone, current_dobj=current_dobj)

        return current_dobj.id
