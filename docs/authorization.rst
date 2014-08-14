.. _authorization:

Authorization
=============

`Authorization <https://en.wikipedia.org/wiki/Authorization>`_ most often
happens after a user is already authenticated and describes the process of
controlling access, i.e. deciding what a user is actually allowed to do.

alcohol provides authorization capabilities in line with the
`NIST RBAC model <https://en.wikipedia.org/wiki/NIST_RBAC_model>`_ (see [1]_).
Four different models are known in the mentioned standard,
of which alcohol currently only supports one, `Flat RBAC`_.

This page illustrates the basic concepts, if you want to dive right into a
practical example, see :doc:`sql`.


Core concepts
-------------

All models have in common that they use the following entities:

* A **user** is usually an abstract or concrete user or other actor. Examples:
  "Alice" or "Webserver #2".
* A **role** is an abstract concept of a function inside an organization.
  Examples: "CEO", "Programmer", "Logging implementation".
* A **permission** enables a role to perform a certain action. Examples:
  "Post new article", "Delete user", "Change role permissions"

At the API level, alcohol makes no assumptions about any of these objects,
although implementations may impose restrictions. For example, the
:class:`~alcohol.rbac.DictRBAC` implementation requires users,
roles and permissions to be hashable.


Flat RBAC
---------

In flat RBAC, five "functional capabilities" are required [2]_:

* Users must acquire permissions through roles [2]_.
* Roles are assigned to users in a many-to-many fashion [2]_.
* Permissions are assigned to roles in a many-to-many fashion [2]_.
* Users may use permissions of multiple roles simultaneously [2]_.
* It must be possible to list all roles assigned to a user [2]_.


A Flat RBAC example
~~~~~~~~~~~~~~~~~~~

The basic `Flat RBAC`_-API is found in :class:`~alcohol.rbac.FlatRBAC`. Here
is an example::

  >>> from alcohol.rbac import DictRBAC
  >>> acl = DictRBAC()
  >>> acl.assign('bob', 'programmer')
  >>> acl.assign('alice', 'ceo')
  >>> acl.assign('alice', 'programmer')

This assigns ``'bob'`` the role of ``'programmer'`` and ``'alice'`` the role
of ``'ceo'`` and ``programmer``. In this case, both users and roles are
strings, but could be any object that supports :func:`hash`. We can query
the ACL to check if we assigned roles correctly:

  >>> acl.get_assigned_roles('bob')
  set(['programmer'])
  >>> sorted(acl.get_assigned_roles('alice'))
  ['ceo', 'programmer']

We can even query for permissions now, even though we expect them all to
fail::

  >>> acl.allowed('bob', 'run_unittests')
  False
  >>> acl.allowed('alice', 'run_unittests')
  False

Users acquire permissions through roles (and only through them!),
so we can add some permissions to these::

  >>> acl.permit('programmer', 'run_unittests')
  >>> acl.permit('ceo', 'hire_and_fire')

This will change our effective permissions::

  >>> acl.allowed('bob', 'run_unittests')
  True
  >>> acl.allowed('bob', 'hire_and_fire')
  False
  >>> acl.allowed('alice', 'run_unittests')
  True
  >>> acl.allowed('alice', 'hire_and_fire')
  True

Permissions are strictly additive, a user has all permissions granted him by
at least one role. Roles can be removed:

  >>> acl.unassign('alice', 'programmer')
  >>> acl.allowed('alice', 'run_unittests')
  False

Permissions can be removed from roles as well:

  >>> acl.revoke('ceo', 'hire_and_fire')
  >>> acl.allowed('alice', 'hire_and_fire')
  False

Finally, it is also possible to query a role to find out if it provides a
specific permission (this goes further than the NIST Flat RBAC requirements)::

  >>> acl.allows('programmer', 'run_unittests')
  True
  >>> acl.allows('programmer', 'hire_and_fire')
  False


.. [1] http://csrc.nist.gov/rbac/sandhu-ferraiolo-kuhn-00.pdf
.. [2] http://csrc.nist.gov/rbac/sandhu-ferraiolo-kuhn-00.pdf, page 4


SQL backend
-----------

An example on how to use this backend is available: :doc:`sql`.

.. autoclass:: alcohol.rbac.sqlalchemy.SQLAlchemyRBAC
