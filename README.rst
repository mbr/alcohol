Alcohol consists of two parts: At its core, it contains a few named `Blinker
<http://pypi.python.org/pypi/blinker/>`_ signals and a precise specification on
how to use them. These signals define a general model for handling user logins
using any sort of credentials and reacting upon them.

In addition to that, alcohol comes some utility code that makes writing
authorization code a lot easier, such as predefined password-hashing methods or
complete mixins for `SQLAlchemy <http://www.sqlalchemy.org/>`_ based user
models.
