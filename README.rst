.. code::

  from alcohol.mixins.sqlalchemy import SQLAlchemyUserMixin

  class User(Base, SQLAlchemyUserMixin):
      id = Column(Integer, primary_key=True)

  bob = User()

  # stores a hash of bobs password (using passlib)
  bob.password = 'bobs_very_secret_password'

  if bob.check_password(some_password):
      print 'hello, bob!'

  # creates a password-reset token that will work once to change his password
  # after he forgot it, signed with the servers secret key
  token = bob.create_password_reset_token(SECRET_KEY)


alcohol is a framework for handling user :doc:`authentication` and
:doc:`authorization`. Both of these parts can be used independently and support
SQLAlchemy_ and in-memory backends.

Authorization is handled using *Role Based Access Controls* (a
`NIST <https://en.wikipedia.org/wiki/NIST>`_-standard) as the underlying
model::

  from alcohol.rbac import DictRBAC

  acl = DictRBAC()
  acl.assign('bob', 'programmer')
  acl.assign('alice', 'ceo')

  acl.permit('programmer', 'run_unittests')
  acl.permit('ceo', 'hire_and_fire')

  acl.allowed('bob', 'run_unittests')    # True
  acl.allowed('bob', 'hire_and_fire')    # False
  acl.allowed('alice', 'hire_and_fire')  # True

.. this should be put back in once flask-alcohol is stable/in better shape
.. While suitable for use in stand-alone, non-web applications it is also a core
.. ingredient to `Flask-Alcohol <http://pypi.python .org/pypi/flask-alcohol/>`_, a
.. `Flask <http://flask.pocoo.org/>`_ library that takes this concept even
.. further.


Utilities
---------

alcohol also ships with a few SQLAlchemy_ mixins for handling updated/modified
timestamps, email fields, password-hashes and generating activation/reset
tokens for the latter two. See :doc:`mixins` for details.


.. [1] http://csrc.nist.gov/rbac/sandhu-ferraiolo-kuhn-00.pdf
.. _SQLAlchemy: http://www.sqlalchemy.org/
