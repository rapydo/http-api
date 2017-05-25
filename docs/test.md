# Writing tests

Tests are performed using [nose2](https://github.com/nose-devs/nose2).
The documentation is [here](http://nose2.readthedocs.io/en/latest/index.html)

## Naming tests
Add a file with a name starting with `test_` under the `test` folder.
In the new file each test function must start with `test_`.
By adding a number in the test function, it is possible to order the execution
of the tests. For instance:

```
def test_01_get_oauthlogin(self):
```

will executed before:

```
def test_02_get_authorize(self):
```

Following this naming convention the new test file will be automatically
discovered by nose2.
See (http://nose2.readthedocs.io/en/latest/usage.html#naming-tests) for more details.

## Fixtures
A test fixture represents the preparation needed to perform one or more tests, 
and any associate cleanup actions. This may involve, for example, creating temporary 
or proxy databases, directories, or starting a server process.
Since we are testing services which run on a Flask server, we have to start
a Flask instance before performing the tests.
To do so, we can use fixtures to automatically start and stop the Flask server
(see https://docs.python.org/3/library/unittest.html#class-and-module-fixtures
for details).

Flask provides a way to test your application by exposing the Werkzeug test Client
and handling the context locals for you (see http://flask.pocoo.org/docs/0.10/testing/)

In the setUpClass add the following code to create a new Flask test client:
```
app = create_app()
app.config['TESTING'] = True
self.app = app.test_client()
```

## Assert
Make use of the several assert methods offered by unittest to check for and
report failures: these methods produce a much more descriptive error in case
of failure.

| Method                    | assertChecks that    |
|---------------------------|----------------------|
| assertEqual(a, b)         | a == b               |
| assertNotEqual(a, b)      | a != b               |
| assertTrue(x)             | bool(x) is True      |
| assertFalse(x)            | bool(x) is False     |
| assertIs(a, b)            | a is b               |
| assertIsNot(a, b)         | a is not b           |
| assertIsNone(x)           | x is None            |
| assertIsNotNone(x)        | x is not None        |
| assertIn(a, b)            | a in b               |
| assertNotIn(a, b)         | a not in b           |
| assertIsInstance(a, b)    | isinstance(a, b)     |
| assertNotIsInstance(a, b) | not isinstance(a, b) |


## An example
Here is an example of test file that you can use as a reference

```
"""
Test  dataobjects endpoints
"""

import io
import os
import json
import unittest
from restapi.server import create_app


__author__ = 'Roberto Mucci (r.mucci@cineca.it)'


class TestDataObjects(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        "set up test fixtures"
        print('### Setting up flask server ###')
        app = create_app()
        app.config['TESTING'] = True
        self.app = app.test_client()

    @classmethod
    def tearDownClass(self):
        "tear down test fixtures"
        print('### Tearing down the flask server ###')

    def test_01_get_verify(self):
        """ Test that the flask server is running and reachable"""

        r = self.app.get('http://localhost:8080/api/verify')
        self.assertEqual(r.status_code, 200)

    def test_02_post_dataobjects(self):
        """ Test file upload: POST """
        # I need to understand who to reapeat the upload test, since
        # overwrite is not allowed
        r = self.app.post('http://localhost:8080/api/dataobjects', data=dict(
                         file=(io.BytesIO(b"this is a test"),
                          'test.pdf')))
        self.assertEqual(r.status_code, 200)  # maybe 201 is more appropriate
```
