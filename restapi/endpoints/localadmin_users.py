# TO BE ENABLED WHEN REQUIRED

# from restapi.models import fields, validate, Schema
# from restapi import decorators
# from restapi.rest.definition import EndpointResource
# from restapi.exceptions import RestApiException, DatabaseDuplicatedEntry
# from restapi.confs import get_project_configuration
# from restapi.services.authentication import BaseAuthentication
# from restapi.services.detect import detector
# from restapi.utilities.globals import mem
# from restapi.endpoints.admin_users import send_notification, parse_roles, parse_group
# from restapi.endpoints.admin_users import get_output_schema
# from restapi.services.authentication import Role

# from restapi.utilities.logs import log


# def get_roles(auth):

#     allowed_roles = get_project_configuration(
#         "variables.backend.allowed_roles",
#         default=[],
#     )

#     roles = {}
#     for r in auth.get_roles():
#         if r.name not in allowed_roles:
#             continue

#         roles[f"roles_{r.name}"] = r.description

#     return roles


# def get_groups():
#     auth_service = detector.authentication_service

#     if auth_service == 'neo4j':

#         groups = []
#         neo4j = detector.get_service_instance('neo4j')

#         # current_user = self.get_user()
#         # for idx, val in enumerate(new_schema):
#         #     # FIXME: groups management is only implemented for neo4j
#         #     if val["name"] == "group":
#         #         new_schema[idx]["default"] = None
#         #         if "custom" not in new_schema[idx]:
#         #             new_schema[idx]["custom"] = {}

#         #         new_schema[idx]["custom"]["htmltype"] = "select"
#         #         new_schema[idx]["custom"]["label"] = "Group"
#         #         new_schema[idx]["enum"] = []

#         #         default_group = self.graph.Group.nodes.get_or_none(
#         #             shortname="default"
#         #         )

#         #         defg = None
#         #         if default_group is not None:
#         #             new_schema[idx]["enum"].append(
#         #                 {default_group.uuid: default_group.shortname}
#         #             )
#         #             # new_schema[idx]["default"] = default_group.uuid
#         #             defg = default_group.uuid

#         #         for g in current_user.coordinator.all():

#         #             if g == default_group:
#         #                 continue

#         #             group_name = f"{g.shortname} - {g.fullname}"
#         #             new_schema[idx]["enum"].append({g.uuid: group_name})
#         #             if defg is None:
#         #                 defg = g.uuid
#         #             # if new_schema[idx]["default"] is None:
#         #             #     new_schema[idx]["default"] = g.uuid
#         #         if (len(new_schema[idx]["enum"])) == 1:
#         #             new_schema[idx]["default"] = defg
#         # for g in neo4j.Group.nodes.all():
#         #     group_name = f"{g.shortname} - {g.fullname}"
#         #     groups.append({g.uuid: group_name})

#         return groups

#     if auth_service == 'sqlalchemy':
#         return None

#     if auth_service == 'mongo':
#         return None

#     log.error("Unknown auth service: {}", auth_service)


# def get_input_schema(strip_required=false, exclude_email=False):

#     set_required = not strip_required
#     auth = EndpointResource.load_authentication()

#     attributes = {}
#     if not exclude_email:
#         attributes["email"] = fields.Email(required=set_required)
#     attributes["password"] = fields.Str(
#         required=set_required,
#         password=True,
#         validate=validate.Length(min=auth.MIN_PASSWORD_LENGTH)
#     )
#     attributes["name"] = fields.Str(
#         required=set_required, validate=validate.Length(min=1))
#     attributes["surname"] = fields.Str(
#         required=set_required, validate=validate.Length(min=1))

#     for key, label in get_roles(auth).items():
#         attributes[key] = fields.Bool(label=label)

#     groups = get_groups()
#     if groups:
#         attributes["group"] = fields.Str(
#             required=True,
#             validate=validate.OneOf(
#                 choices=groups.keys(),
#                 labels=groups.values()
#             )
#         )
#     if custom_fields := mem.customizer.get_custom_input_fields(strip_required):
#         attributes.update(custom_fields)

#     if detector.check_availability("smtp"):
#         attributes["email_notification"] = fields.Bool(
#             label="Notify password by email"
#         )

#     return Schema.from_dict(attributes)


# class LocalAdminUsers(EndpointResource):

#     auth_service = detector.authentication_service
#     neo4j_enabled = auth_service == 'neo4j'
#     sql_enabled = auth_service == 'sqlalchemy'
#     mongo_enabled = auth_service == 'mongo'

#     depends_on = ["not ADMINER_DISABLED"]
#     labels = ["admin"]

#     def is_authorized(self, current_user, user, is_admin):

#         if user is None:
#             return False

#         # an ADMIN is always authorized
#         # if is_admin:
#         #     return True

#         # If you are not an ADMIN, you cannot modify yourself...
#         # use the profile instead!
#         if current_user == user:
#             return False

#         # You cannot modify ADMINs
#         if ADMIN in self.auth.get_roles_from_user(user):
#             return False

#         # FIXME: groups management is only implemented for neo4j
#         if self.neo4j_enabled:
#             # You are a local admin... but the group matches??
#             for g in current_user.coordinator.all():
#                 if user.belongs_to.is_connected(g):
#                     return True

#             # All local admins have rights on general users
#             g = self.graph.Group.nodes.get_or_none(shortname="default")
#             if g is not None:
#                 if user.belongs_to.is_connected(g):
#                     return True

#         return False

#     @decorators.auth.require_all(Role.LOCAL_ADMIN)
#     @decorators.marshal_with(get_output_schema(), code=200)
#     @decorators.endpoint(
#         path="/localadmin/users",
#         summary="List of users",
#         responses={
#             200: "List of users successfully retrieved",
#         },
#     )
#     @decorators.endpoint(
#         path="/localadmin/users/<user_id>",
#         summary="Obtain information on a single user",
#         responses={
#             200: "User information successfully retrieved",
#         },
#     )
#     def get(self, user_id=None):

#         data = []

#         is_admin = self.verify_admin()

#         users = self.auth.get_users(user_id)
#         if users is None:
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )
#         if self.neo4j_enabled:
#             self.graph = self.get_service_instance('neo4j')

#         current_user = self.get_user()
#         for user in users:

#             if not self.is_authorized(current_user, user, is_admin):
#                 continue

#             data.append(user)

#         return self.response(data)

#     @decorators.auth.require_all(Role.LOCAL_ADMIN)
#     @decorators.use_kwargs(get_input_schema())
#     @decorators.endpoint(
#         path="/localadmin/users",
#         summary="Create a new user",
#         responses={
#             200: "The uuid of the new user is returned",
#             409: "This user already exists",
#         },
#     )

#     def post(self, **kwargs):

#         roles, roles_keys = parse_roles(kwargs)
#         for r in roles_keys:
#             kwargs.pop(r)

#         allowed_roles = get_project_configuration(
#             "variables.backend.allowed_roles",
#             default=[],
#         )

#         for r in roles:
#             if r not in allowed_roles:
#                 raise RestApiException(
#                     "You are not allowed to assign users to this role"
#                 )

#         unhashed_password = kwargs["password"]

#         # If created by admins users must accept privacy at first login
#         kwargs['privacy_accepted'] = False

#         try:
#             user = self.auth.create_user(kwargs, roles)
#             if self.sql_enabled:
#                 self.auth.db.session.commit()
#         except DatabaseDuplicatedEntry as e:
#             if self.sql_enabled:
#                 self.auth.db.session.rollback()
#             raise RestApiException(str(e), status_code=409)

#         # FIXME: groups management is only implemented for neo4j
#         if 'group' in kwargs and self.neo4j_enabled:
#             self.graph = self.get_service_instance('neo4j')
#             group = parse_group(kwargs, self.graph)

#             if group is not None:
#                 if group.shortname != "default":
#                     current_user = self.get_user()
#                     if not group.coordinator.is_connected(current_user):
#                         raise RestApiException(
#                             "You are not allowed to assign users to this group"
#                         )

#                 user.belongs_to.connect(group)

#         email_notification = kwargs.get('email_notification', False)
#         if email_notification and unhashed_password is not None:
#             send_notification(user, unhashed_password, is_update=False)

#         return self.response(user.uuid)

#     @decorators.auth.require_all(Role.LOCAL_ADMIN)
#     @decorators.use_kwargs(get_input_schema(strip_required=True, exclude_email=True))
#     @decorators.endpoint(
#         path="/localadmin/users/<user_id>",
#         summary="Modify a user",
#         responses={
#             200: "User successfully modified",
#         },
#     )
#     def put(self, user_id, **kwargs):

#         user = self.auth.get_users(user_id)

#         if user is None:
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

#         user = user[0]

#         current_user = self.get_user()
#         is_admin = self.verify_admin()
#         if not self.is_authorized(current_user, user, is_admin):
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

#         if "password" in kwargs:
#             unhashed_password = kwargs["password"]
#             kwargs["password"] = BaseAuthentication.get_password_hash(
#                 kwargs["password"]
#             )
#         else:
#             unhashed_password = None

#         roles, roles_keys = parse_roles(kwargs)
#         for r in roles_keys:
#             kwargs.pop(r)

#         allowed_roles = get_project_configuration(
#             "variables.backend.allowed_roles",
#             default=[],
#         )

#         for r in roles:
#             if r not in allowed_roles:
#                 raise RestApiException(
#                     "You are not allowed to assign users to this role"
#                 )

#         self.auth.link_roles(user, roles)

#         db = self.get_service_instance(detector.authentication_service)
#         db.update_properties(user, kwargs)
#         self.auth.save_user(user)

#         # FIXME: groups management is only implemented for neo4j
#         if 'group' in kwargs and self.neo4j_enabled:

#             group = parse_group(kwargs, self.Graph)

#             if group.shortname != "default":
#                 if not group.coordinator.is_connected(current_user):
#                     raise RestApiException(
#                         "You are not allowed to assign users to this group"
#                     )

#             p = None
#             for p in user.belongs_to.all():
#                 if p == group:
#                     continue

#             if p is not None:
#                 user.belongs_to.reconnect(p, group)
#             else:
#                 user.belongs_to.connect(group)

#         email_notification = kwargs.get('email_notification', False)
#         if email_notification and unhashed_password is not None:
#             send_notification(user, unhashed_password, is_update=True)

#         return self.empty_response()

#     @decorators.auth.require_all(Role.LOCAL_ADMIN)
#     @decorators.endpoint(
#         path="/localadmin/users/<user_id>",
#         summary="Delete a user",
#         responses={
#             200: "User successfully deleted",
#         },
#     )
#     def delete(self, user_id):

#         is_admin = self.verify_admin()
#         if self.neo4j_enabled:
#             self.graph = self.get_service_instance('neo4j')

#         user = self.auth.get_users(user_id)

#         if user is None:
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

#         user = user[0]

#         current_user = self.get_user()
#         if not self.is_authorized(current_user, user, is_admin):
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

#         if self.neo4j_enabled:
#             user.delete()
#         elif self.sql_enabled:
#             self.auth.db.session.delete(user)
#             self.auth.db.session.commit()
#         elif self.mongo_enabled:
#             user.delete()
#         else:
#             raise RestApiException("Invalid auth backend, all known db are disabled")

#         return self.empty_response()
