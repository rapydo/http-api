# from restapi import decorators
# from restapi.rest.definition import EndpointResource
# from restapi.endpoints.admin_users import get_output_schema
# from restapi.services.authentication import Role

# # from restapi.utilities.logs import log

# ################################################
# #   THIS IS THE NEW READ-ONLY IMPLEMENTATION   #
# ################################################

# class GroupUsers(EndpointResource):

#     depends_on = ["MAIN_LOGIN_ENABLE"]
#     labels = ["admin"]

#     @decorators.auth.require_all(Role.COORDINATOR)
#     @decorators.marshal_with(get_output_schema(), code=200)
#     @decorators.endpoint(
#         path="/group/users",
#         summary="List of users of your group",
#         responses={
#             200: "List of users successfully retrieved",
#         },
#     )
#     def get(self):

#         users = self.auth.get_users()
#         current_user = self.get_user()

#         if Connector.authentication_service == "neo4j":
#             current_user.belongs_to = current_user.belongs_to.single()

#         data = []
#         # Should iterate over current_user.belong_to.users instead of on all
#         for user in users:

#             if Connector.authentication_service == "neo4j":
#                 user.belongs_to = user.belongs_to.single()

#             if current_user.belongs_to != user.belongs_to:
#                 continue

#             data.append(user)

#         return self.response(data)

# #############################################################
# #   THIS IS THE OLD IMPLEMENTATION WITH WRITE PERMISSIONS   #
# #############################################################

# from restapi.config import get_project_configuration
# from restapi.services.authentication import BaseAuthentication
# from restapi.endpoints.admin_users import send_notification, parse_roles, parse_group
# from restapi.utilities.globals import mem

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
#     auth_service = Connector.authentication_service

#     if auth_service == 'neo4j':

#         groups = []
#         graph = neo4j.get_instance()

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

#         #         default_group = graph.Group.nodes.get_or_none(
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
#         # for g in graph.Group.nodes.all():
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
#     auth = Connector.get_authentication_instance()

#     # as defined in Marshmallow.schema.from_dict
#     attributes: Dict[str, Union[fields.Field, type]] = {}
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
#     if custom_fields := mem.customizer.get_custom_input_fields(
#         strip_required, scope=mem.customizer.ADMIN
#     ):
#         attributes.update(custom_fields)

#     if Connector.check_availability("smtp"):
#         attributes["email_notification"] = fields.Bool(
#             label="Notify password by email"
#         )

#     return Schema.from_dict(attributes, name="GroupDefinition")

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
#         if Role.ADMIN in self.auth.get_roles_from_user(user):
#             return False

#         # FIXME: groups management is only implemented for neo4j
#         if self.neo4j_enabled:
#             # You are a local admin... but the group matches??
#             for g in current_user.coordinator.all():
#                 if user.belongs_to.is_connected(g):
#                     return True

#             # All local admins have rights on general users
#             g = graph.Group.nodes.get_or_none(shortname="default")
#             if g is not None:
#                 if user.belongs_to.is_connected(g):
#                     return True

#         return False

#     @decorators.auth.require_all(Role.COORDINATOR)
#     @decorators.use_kwargs(get_input_schema())
#     @decorators.endpoint(
#         path="/group/users",
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
#             graph = neo4j.get_instance()
#             group = parse_group(kwargs, graph)

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
#         self.log_event(self.events.create, user, kwargs)
#         return self.response(user.uuid)

#     @decorators.auth.require_all(Role.COORDINATOR)
#     @decorators.use_kwargs(get_input_schema(strip_required=True, exclude_email=True))
#     @decorators.endpoint(
#         path="/group/users/<user_id>",
#         summary="Modify a user",
#         responses={
#             200: "User successfully modified",
#         },
#     )
#     def put(self, user_id, **kwargs):

#         user = self.auth.get_user(user_id=user_id)

#         if user is None:
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

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

#         self.auth.db.update_properties(user, kwargs)
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
#         self.log_event(self.events.modifiy, user, kwargs)
#         return self.empty_response()

#     @decorators.auth.require_all(Role.COORDINATOR)
#     @decorators.endpoint(
#         path="/group/users/<user_id>",
#         summary="Delete a user",
#         responses={
#             200: "User successfully deleted",
#         },
#     )
#     def delete(self, user_id):

#         is_admin = self.verify_admin()
#         if self.neo4j_enabled:
#             graph = neo4j.get_instance()

#         user = self.auth.get_user(user_id=user_id

#         if user is None:
#             raise RestApiException(
#                 "This user cannot be found or you are not authorized"
#             )

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
#         self.log_event(self.events.delete, user)
#         return self.empty_response()
