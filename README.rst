alcohol is a micro-framework for handling user
`authentication <https://en.wikipedia.org/wiki/Authentication>`_ and
`authorization <https://en.wikipedia.org/wiki/Authorization>`_. Both of
these parts can be used indenpendently from each other
and consist of well-defined interfaces and some convenient implementations
for these, support in-memory ACLs and
SQLAlchemy_.

In addition to that, alcohol comes some utility code that makes writing
authorization code a lot easier, such as predefined password-hashing methods or
complete mixins for SQLAlchemy_ based user models.

.. this should be put back in once flask-alcohol is stable/in better shape
.. While suitable for use in stand-alone, non-web applications it is also a core
.. ingredient to `Flask-Alcohol <http://pypi.python .org/pypi/flask-alcohol/>`_, a
.. `Flask <http://flask.pocoo.org/>`_ library that takes this concept even
.. further.

Authentication
--------------

.. warning:: The authentication part of alcohol is still under development and
             its API may undergo even conceptual changes in the future. This
             does not apply for the authorization module.

`Authentication <https://en.wikipedia.org/wiki/Authentication>`_ is the act
of confirming that a user (or another actor in your system) is who he/she/it
says. A very common method to authenticate users, for example, is to ask them
for a password - if they know the correct password, the system assumes their
identity is accurate.

alcohol is not tied to a specific way of authenticating users (like
passwords) and can support many different kinds. You can read  more about
its authentication capabilities in the :ref:`authentication`-section.


Authorization
-------------

`Authorization <https://en.wikipedia.org/wiki/Authorization>`_ most often
happens after a user is already authenticated and describes the process of
controlling access, i.e. deciding what a user is actually allowed to do.

To do this, alcohol uses `Role-based access control <https://en.wikipedia
.org/wiki/Role-based_access_control>`_, specifically an interface modeled
after the standardized `NIST RBAC model <https://en.wikipedia
.org/wiki/NIST_RBAC_model>`_ (the related paper can be found at [1]_).

This is described in-depth in the :ref:`authorization`-section.


Utilities
---------

alcohol also ships with a few utilities, like mixins for SQLAlchemy_-based
User classes, adding password hashing and checking capabilities. See
:doc:`mixins` and :doc:`tokengen` for details.


.. [1] http://csrc.nist.gov/rbac/sandhu-ferraiolo-kuhn-00.pdf
.. _SQLAlchemy: http://www.sqlalchemy.org/
