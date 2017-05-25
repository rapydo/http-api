
# A code base/framework for your modern RESTful HTTP API 

A Python **3** Flask HTTP server mapping custom classes into REST API endpoints;
written with **the base** in mind for middleware APIs in our projects.

It comes bundled with:

* RESTful classes to write endpoints
* decorators to add properties and parameters
* as many best practices i found in my experience for Flask
* easy configuration
* any database/resource pluggable (in fact, you can write your own)
* sqlalchemy (sqllite as default) backend
* security handling (JWT and your database of choice)
* administration

---

## Documentation

**WARNING:
the documentation is outdated, i will try to fix it anytime soon**

You can find a compiled version on
[readthedocs website](http://http-api-base.readthedocs.io/en/latest/).
<!--
[readthedocs website](http://rest-mock.readthedocs.org/en/latest/)
-->

Here is the index for browsing it internally on GitHub:

* [Introduction](docs/index.md)
* [Quick start](docs/quick.md)
* [Configuration](docs/conf.md)
* [Run the server](docs/run.md)
* [Manage APIs](docs/manage.md)
* [Security](docs/security.md)
* [Testing](docs/test.md)

---

## Creator

* [Paolo D'Onorio De Meo](https://twitter.com/paolodonorio/) - (Please [Say Thanks!](https://saythanks.io/to/pdonorio) if this helped you in anyway `^_^`)

## Other contributors

* Mattia D'Antonio (@mdantonio)
* Roberto Mucci (@muccix)

## Copyright and license

Code and documentation copyright: `Paolo D'Onorio De Meo @2015`.

Code released under the [MIT license](LICENSE).
