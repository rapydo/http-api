
# Built-in services

Instead of re-writing over and over the services i use most often,
i prefer to leave the generic part (e.g. a db connection and driver)
already available inside the`resources.services` package.

Here is the list of what i am trying to inject for the first release:

 - Rethinkdb: nosql json + joins + changefeed @beta
 - Neo4j graphdb @inprogress
 - Uploader @inprogress
 - Irods virtual resources @todo
 - Elasticsearch @justadraft

## Neo4j Graph database

To add this service to your APIs you need to follow some steps:

**1** - Add the graphdb container

Inside your YML file you must add the [official neo4j docker image](http://neo4j.com/developer/docker/):

```yaml
mygraph:
    image: neo4j
    environment:
        NEO4J_AUTH: neo4j/chooseapassword

```

**2** - Link the graphdb container to your backend

```yaml
mybackend:
    image: pdonorio/py3api
    command: ./boot devel
    links:
        - mygraph:gdb
```

**IMPORTANT**: the linked service MUST be called `gdb`!

**3** - Import the service inside your python file

```python
from ..base import ExtendedApiResource
from .. import decorators as decorate
from ..services.neo4j import migraph

class MyAPI(ExtendedApiResource):

    @decorate.apimethod
    def get(self):
        result = migraph.cipher("MATCH (n)")
        return result
```

Note: Importing the service you will create a graphdb connection.
