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
#             # To be replaced with Neo4jRelationshipToSingle
#             current_user.belongs_to = current_user.belongs_to.single()

#         data = []
#         # Should iterate over current_user.belong_to.users instead of on all
#         for user in users:

#             if Connector.authentication_service == "neo4j":
#                 # To be replaced with Neo4jRelationshipToSingle
#                 user.belongs_to = user.belongs_to.single()

#             if current_user.belongs_to != user.belongs_to:
#                 continue

#             data.append(user)

#         return self.response(data)
