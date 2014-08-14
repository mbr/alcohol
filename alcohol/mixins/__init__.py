#!/usr/bin/env python
# coding=utf8

from binascii import hexlify
import os

from itsdangerous import TimestampSigner, BadData, URLSafeTimedSerializer
import passlib.apps


DAY = 60 * 60 * 24


class PasswordMixin(object):
    """A mixin that stores a key based on a password. An attribute named
    `_pwhash` will be used to store the password hash."""
    crypt_context = passlib.apps.custom_app_context  # overridable default

    def check_password(self, password):
        """Check if a supplied password is the same as the user's password.

        :param password: Password to be checked.
        :return: ``True`` if valid, ``False`` otherwise.
        """
        return self.crypt_context.verify(password, self._pwhash)

    def _create_signer(self, secret_key):
        return TimestampSigner(secret_key, self._pwhash, key_derivation='hmac')

    def check_password_reset_token(self, secret_key, token, max_age_sec=DAY):
        """Checks if a supplied password-reset token is valid.

        :param secret_key: Your applications secret key.
        :param password: Password-reset token to be checked.
        :param max_age_sec: The maximum age in seconds this token may be old
                            before its considered expired. Default is 24 hours.
        :return: ``True`` if valid, ``False`` otherwise.
        """

        signer = self._create_signer(secret_key)
        try:
            signer.unsign(token, max_age=max_age_sec)
            return True
        except BadData:
            return False

    def create_reset_password_token(self, secret_key, random_source=os.urandom,
                                    nonce_size=5):
        """Create a signed password reset token.

        A pasword reset token using a key derived from ``secret_key`` and
        the current password hash, causing it to stop working once the password
        has been altered.

        It also includes a nonce, so that attackers cannot tell whether a
        password-reset request has been made twice for the same password.

        :param secret_key: The application's own secret key.
        :param random_source: The random source to use to create the nonce.
                              Defaults to :func:`os.urandom`.
        :param nonce_size: Number of bytes in the nonce. Each additional byte
                           will increase the resulting tokens length by 2.
        :return: An urlsafe string.
        """

        # sign a few random bytes to hide repetitions
        signer = self._create_signer(secret_key)
        return signer.sign(hexlify(random_source(nonce_size)))

    @property
    def password(self):
        """The users password. This is a write-only property, attempting to
        read it will throw an exception. Use this to set the users password."""
        raise TypeError(
            'password property is write-only, use check_password'
        )

    @password.setter
    def password(self, new_password):
        self._pwhash = self.crypt_context.encrypt(new_password)


class EmailMixin(object):
    """Adds an ``email`` attribute and supports generating email activation
    tokens."""

    email = None
    """An email address. Not validated in any form."""

    def _create_serializer(self, secret_key):
        return URLSafeTimedSerializer(
            secret_key, self.email, signer_kwargs={'key_derivation': 'hmac'}
        )

    def activate_email(self, secret_key, token, max_age_sec=DAY):
        """Checks if the email activation token is valid. If it is, updates the
        users email address with the one saved in the token.

        :param secret_key: The application's own secret key.
        :param token: The activation token.
        :param max_age_sec: The maximum age in seconds this token may be old
                            before its considered expired. Default is 24 hours.

        :return: ``True`` if the activation was successful, ``False``
                otherwise."""

        serializer = self._create_serializer(secret_key)
        try:
            self.email = serializer.loads(token, max_age=max_age_sec)
            return True
        except BadData:
            return False

    def create_email_activation_token(self, secret_key, email):
        """Creates a new activation token that allows changing the email
        address. The token will tied to the old email address and works only
        if the address has not changed in the meantime.

        :param secret_key: The application's own secret key.
        :param email: The desired new email address. Will be encoded inside
                      the token.
        :return: An urlsafe string.
        """

        return self._create_serializer(secret_key).dumps(email)
