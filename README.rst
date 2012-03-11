Alcohol consists of two parts: At its core, it contains a few named `Blinker
<http://pypi.python.org/pypi/blinker/>`_ signals and a precise specification on
how to uses them. These signals define a general model for handling user logins
using any sort of credentials and reacting upon them.

In addition to that, alcohol comes some utility code that makes writing
authorization code a lot easier, such as predefined password-hashing methods or
complete mixins for `SQLAlchemy <http://www.sqlalchemy.org/>`_ based user
models.

While suitable for use in stand-alone, non-web applications it is also a core
ingredient to `Flask-Alcohol <http://pypi.python.org/pypi/flask-alcohol/>`_, a
`Flask <http://flask.pocoo.org/>`_ library that takes this concept even
further.
