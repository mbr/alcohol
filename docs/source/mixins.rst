Mixin classes
=============
Built on top of :py:mod:`alcohol.tokengen`, a few mixin classes are available
providing functionality commonly needed when handling users.

.. automodule:: alcohol.mixins
   :members:

.. py:class:: alcohol.mixins.PasswordMixin

   A mixin that stores a key based on a password. An attribute named `_pwhash`
   will be used to store the password hash.

   Note that this class cannot be instantiated directly, instead call
   :py:func:`password_mixin` first to get an instance of the class object first
   which can be mixed into your model classes.

   .. py:attribute:: password

      The users password. This is a write-only property, attempting to read it
      will throw an exception. Use this to set the users password.

   .. py:method:: check_password(password)

      Check if a supplied password is the same as the user's password.

      :param password: Password to be checked.
      :return: True if valid, False otherwise.

   .. py:method:: check_password_reset_token(token)

      Checks if a supplied password-reset token is valid.

      :param password: Password-reset token to be checked.
      :return: True if valid, False otherwise.

   .. py:method:: create_password_reset_token(valid_for=60*60*24)

      Creates a new reset token, which will be valid until it expires or until
      the password is changed once.

      :param valid_for: How long the token should be valid.
      :return: A new password reset token (as a string).


.. py:class:: alcohol.mixins.EmailMixin

   A mixin that uses the attributes `email` and `unverified_email`  and
   supports the generation of tokens to activate the user supplied address.

   When changing a users email address, set it to `unverified_email`, create an
   activation token, mail it to the user and have him enter it back. After
   that, call :py:meth:`~alcohol.mixin.EmailMixin.activate_email` to activate
   it.

   You can skip this part if you want a users email to be activated directly by
   simply assigning it to `email` instead.

   Note that this class cannot be instantiated directly, instead call
   :py:func:`email_mixin` first to get an instance of the class object first
   which can be mixed into your model classes.

   .. py:attribute:: email

      A user's email that has been activated. Before activation of any email,
      this field is `None`.

   .. py:attribute:: unverified_email

      The "candidate email", a mail address provided by the user that he has
      not activated yet.

   .. py:method:: activate_email(token)

      Checks if the email activation token is valid. If so, move the value from
      `unverified_email` to `email` and unset `unverified_email`.

      :param token: The token supplied by the user.
      :return: True if the activation was successful, False otherwise.

   .. py:method:: create_email_activation_token(valid_for=60*60*24)

      Creates a new activation token, which will be valid until it expires or
      until the unverified email changes.

      :param valid_for: How long the token should be valid.
      :return: A new email activation token (as a string).


Specialized mixins
------------------

There are two submodules available, one for `SQLAlchemy
<http://sqlalchemy.org>`_ and one for `Google App Engine ndb
<https://developers.google.com/appengine/docs/python/ndb/>`_. These can be
mixed in, saving you the trouble of defining the colums/fields on the model
objects manually.

.. automodule:: alcohol.mixins.sqlalchemy
   :members:

.. automodule:: alcohol.mixins.gaendb
   :members:

.. py:class:: alcohol.mixins.sqlalchemy.TimestampMixin

   A mixin that adds two timestamp fields, `created` and `modified`. The
   `created` timestamp is updated only on creation, while every SQL UPDATE will
   trigger a refresh of the `modified` timestamp.

   Note that this class cannot be instantiated directly, instead call
   :py:func:`timestamp_mixin` first to get an instance of the class object
   first which can be mixed into your model classes.

   .. py:attribute:: created

      A :py:class:`datetime.datetime` instance containing the time this record
      was created.

   .. py:attribute:: modified

      A :py:class:`datetime.datetime` instance containing the time this record
      was last modified.
