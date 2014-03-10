alcohol
=======
alcohol is a micro-framework for handling user identification and
authorization. Both of these parts can be used indenpendently from each other
and consist of well-defined interfaces and some convenient implementations
for these.


Authentication
--------------

`Authentication <https://en.wikipedia.org/wiki/Authentication>`_ is the act
of confirming that a user (or another actor in your system) is who he/she/it
says. A very common method to authenticate users, for example,is to ask them
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

.. [1] http://csrc.nist.gov/rbac/sandhu-ferraiolo-kuhn-00.pdf


Table of contents
-----------------

While high level interfaces are described in the relevant sections,
alcohol also contains a few extras and ready-to-use implementations for some
common cases.


.. toctree::

   authentication
   authorization
   extras
   tokengen
   mixins
   changes
