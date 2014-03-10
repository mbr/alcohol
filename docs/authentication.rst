.. _authentication:

Authentication
==============

The flow of the library components revolves heavily around a signal named
:data:`~alcohol.user_id_changed`.

1. Any time a handler processes some sort of request, if a valid login, is
   found, it sends the :data:`~alcohol.user_id_changed` signal.
2. Any number of processors can bind to the
   :data:`~alcohol.user_id_changed` signal and perform actions
   upon receiving it. Two of the most common examples are storing the currently
   logged in user on the application's thread locals and storing the user id in
   some sort of persistance layer.


Terminology
-----------
A couple of terms are used in a precise fashion within alcohol.

User-ID
~~~~~~~
Every user must have an internal unique id that can be represented as a
string. If they are not strings, a serialization scheme should be used to
convert them to binary (not unicode) string values and back.

While a user can have multiple means of identification (for example, he might
be able to login with his email as well as any number of OpenID accounts),
the User-ID must be unique, should never change and never be reused for another
user.

User
~~~~
A User is any kind of value, for an example an instance of a ``User``-class
that is identified by the User-ID. alcohol imposes no restriction on what
can be a User instance and in general handles User-IDs instead.


The ``user_id_changed`` signal
------------------------------
The :data:`~alcohol.user_id_changed` signal is at the core of
alcohol and communicates all information about user logins:

.. data:: alcohol.user_id_changed

          Sent when any handler has found a valid User-ID. Arguments are
          :data:`user_id_changed(sender, user_id, **kwargs)`

          :param sender: The sender that sent the siganl.
                          This allows using :meth:`blinker.base.Signal.connect_via`
                      to bind to a specific sender.

          :param user_id: The (canonical) string representation of the User-ID
                              that should now be active.

              :param **kwargs: Any number of extra options. Every receiver must
                               accept keyword arguments, even if he does not handle
                               any.  These are used to add additional information
                               about the nature of the id change.


Signal options
~~~~~~~~~~~~~~
While a sender is free to add any number of options to the
``kwargs``-parameter, a few standard option names (that need not be present)
are reserved:

- **restored**: Set to `True`, if the User-ID changed not due to a login or
  "active" action by the user, but rather was restored from
  some persistance layer. A typical example is the loading of a
  User-ID from a cookie in a web application.
- **expire_on**: If present, the user requested that his login be limited. A
  value equivalent to an integer 0 means do not persist permanently
  (i.e. persistance should be limited in a manner similiar to a session
  cookie), otherwise this value should be a :py:class:`~datetime.datetime`
  object set to when the login should expire.


The ``user_id_reset`` signal
----------------------------
Emitted when something that is similiar to a "logout" occured, the
:data:`~alcohol.user_id_reset` signal tells other components that from now on,
the ``user_id`` should be considered ``None``.

.. data:: alcohol.user_id_reset

          Sent when a handler has determined that the global User-ID should be
          reset to ``None``.

          :param sender: The sender.
              :param **kwargs: Extra options, as in :data:`~alcohol.user_id_changed`.
                           Currently, none are known.

