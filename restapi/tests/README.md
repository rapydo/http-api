## Utilities to write tests ##

This collection of utilities is meant to simplify the writing of endpoints tests with the assumption that the endpoints following some conventions:

-   endpoints accepting POST data should provide a json schema to describe the required information

            schema = [
                {
                    "key": "unique-key-name-of-this-field",
                    "type": "text/int",
                    "required": "true/false",
                },
                {
                    "key": "unique-key-name-of-this-field",
                    "type": "select",
                    "required": "true/false",
                    "options": [
                        {"id": "OptionID", "value": "OptionValue"},
                        ...
                    ]
                },
                ...
            ]

-   endpoints should return responses using a standard json as describe in <http://jsonapi.org>

-   endpoint should accept GET/POST/PUT and DELETE calls with no parameters and return respectively 200 400 400 400 status codes

-   POST endpoints when successfull should return and created entity id. This id should be valid for further PUT and DELETE calls

-   PUT and DELETE endpoints should respond on the same endpoints of POST method with the addition of the entity id, e.g.:

    -   POST /api/myendpoint

    -   PUT /api/myendpoint/_id_

    -   DELETE /api/myendpoint/_id_

-   Successfully should returns 200 OK (if GET or POST) and 204 NO CONTENT (if PUT and DELETE)

# OBSOLETE DOC #
## How to use the Test Utilities ##

Your own test class should import and extend test utilities

	from utilities.tests.utilities import TestUtilities

		class YourTests(TestUtilities):
			pass

### Save variables and re-use it in other tests of your class ###

	my_var = 'usefull information'
	self.save("my-variable", my_var)
	...
	previous_info = self.get("my-variable")

### Make login and save tokens and headers for further calls ###

	from restapi.confs.config import USER, PWD
	headers, token = self.do_login(USER, PWD)
	self.save("headers", headers)
	self.save("token", token)

### Make basic test on endpoints ###

	self._test_endpoint(
		your_endpoint,
		headers=headers,
		private_get=False,
		private_post=True,
		private_put=None,
		private_delete=True
	)

-   private=False -> test if the method exists
   -   GET -> 200 OK
   -   POST/PUT/DELETE -> 400 BAD REQUEST
-   private=True    -> test if the method exists and requires a token
   -   no token -> 401 UNAUTHORIZED
   -   with token -> 200 OK / 400 BAD REQUEST
-   private=None    -> test if the method do not exist
   -   all methods -> 405 NOT ALLOWED

In the previous example GET is tested as public, POST and DELETE as private and PUT as not implemented.
Expected returned status code are
-   GET: 200
-   POST: 401 without token and 400 with token
-   PUT: 405
-   DELETE: 401 without token and 400 with token

### Build random data to test POST and PUT endpoints ###

Your APIs should return a json schema as described above. Once you obtained the json schema you can build random data by using the buildData utility

	data = self.buildData(schema)

To test endpoint behaviours when receiving partial data you can use the getPartialData utility

	partial_data = self.buildData(schema, data)

This method takes as input both json schema and built data and remove one of the required fields

### Test endpoints with specific conditions ###

You can test your endpoints by simulating your own conditions by using the utility methods:
-   _test_get
-   _test_create
-   _test_update
-   _test_delete

All methods take as input the endpoint, the headers (should be made optional, now is a required input) and a return status. As optional a returned errors can also be provided.
Create and update also require a pre-built data dictionary.
As option delete can take as input the data dictionary.

This utility returns a response content (content['Response']['data'])3
When parse_response=True, the returned response is parsed using self.parseResponse mnethod

This utility tests the returned status code. If it matches and the response has a content (status != NO_CONTENT) and an error is provided, it is matched against content['Response']['errors']

If requested the returned responses is parsed using the parseResponse utility

### Parsed response ###

To test and simplify the access to json-standard-responses (as described in <http://jsonapi.org>) thid method create an Object filled with attributes obtained by mapping json content

```python
    obj = ParsedResponse()
    obj._id = response["id"]
    obj._type = response["type"]
    obj._links = response["links"]
    obj.attributes.item1Key = response["attributes"][item1Key]
    obj.attributes.item2Key = response["attributes"][item2Key]
    obj._relatedItem1 = recursiveCallOnInnerElement(response["relationships"][relatedItem1]
    obj._relatedItem2 = recursiveCallOnInnerElement(response["relationships"][relatedItem2]
```

Example:

INPUT:

	{
                "attributes": {
                    "access_type": "inherit",
                    "accession": "CRD00000013493",
                    "created": "1466659830",
                    "description": "test",
                    "modified": "1467103075",
                    "name": "My name",
                    "nfiles": 0
                },
                "id": "1724c562-8cab-4178-8b19-3823e1725d46",
                "relationships": {
                    "ownership": [
                        {
                            "attributes": {
                                "email": "myself@myemail.com",
                                "name": "MyName",
                                "surname": "MySurname"
                            },
                            "id": "-",
                            "type": "user"
                        }
                    ],
                    "sample": [
                        {
                            "attributes": {
                                "accession": "CRN00000014466",
                                "age": 89,
                                "cell": "-",
                                "description": "sample descr",
                                "name": "sample name",
                                "tissue": "-"
                            },
                            "id": "716e0883-2459-4136-88bd-88aaaece35fd",
                            "relationships": {
                                "father": [],
                                "mother": [],
                                "organism": [
                                    {
                                        "attributes": {
                                            "common_name": "House mouse",
                                            "scientific_name": "Mus Musculus",
                                            "short_name": "mouse",
                                            "taxon_id": 10090
                                        },
                                        "id": "-",
                                        "type": "organism"
                                    }
                                ],
                                "son": []
                            },
                            "type": "sample"
                        }
                    ],
                },
                "type": "dataset"
        }

OUTPUT:

	obj.type = "dataset"
	obj.id = "1724c562-8cab-4178-8b19-3823e1725d46"
	obj.attributes.access_type = "inherit"
	obj.attributes.accession = "CRD00000013493"
	obj.attributes.created = "1466659830"
	obj.attributes.description = "test"
	obj.attributes.modified = "1467103075"
	obj.attributes.name = My name"
	obj.attributes.nfiles= 0

	obj._ownership.type = "user"
	obj._ownership.id = "-"
	obj._ownership.attributes.email = "myself@myemail.com"
	obj._ownership.attributes.name = "MyName"
	obj._ownership.attributes.surname = "MySurname"

	obj._sample.type = "sample"
	obj._sample.id = "716e0883-2459-4136-88bd-88aaaece35fd"
	obj._sample.attributes.accession = "CRN00000014466"
	obj._sample.attributes.age = 89,
	obj._sample.attributes.cell = "-"
	obj._sample.attributes.description = "sample descr"
	obj._sample.attributes.name = "sample name"
	obj._sample.attributes.tissue = "-"
	obj._sample._organism.type = "organism"
	obj._sample._organism.id = "-"
	obj._sample._organism.attributes.common_name = "House mouse"
	obj._sample._organism.attributes.scientific_name = "Mus Musculus"
	obj._sample._organism.attributes.short_name = "mouse"
	obj._sample._organism.attributes.taxon_id = 10090

### Verify the content of the response ###

You can verify that the response returned by your endpoint, contains expected field and relationships by using the checkResponse utility (a parsed response is required as input)

	response = self._test_get(endpoint, headers, OK)
	required_fields = ['accession', 'name', 'description', 'nfiles', 'created', 'modified', 'access_type']
	required_relationships = ['ownership', 'sample']
	self.checkResponse(response, required_fields, required_relationships)

### Automatic verification of troublesome conditions ###

Based on the input field type POST and PUT method can be can be overwhelmed by particular inputs (for example strings contained quotes or very long numbers)

Based on the input type described in the json schema, the _test_troublesome_create utility can verify the behaviour on an endpoint when such conditions occur. This method expect specific status codes for each trouble test but expected status code can be overwritten by providing a status_configuration dictionary.
When POST calls return a 200 OK PUT and DELETE are also called

	# Overwrite expected status code for NEGATIVE_NUMBER and LONG_NUMBER tests
	status_conf = {}
	status_conf["NEGATIVE_NUMBER"] = BAD_REQUEST
	status_conf["LONG_NUMBER"] = BAD_REQUEST

	self._test_troublesome_create(my_endpoint, headers, schema, status_conf)
