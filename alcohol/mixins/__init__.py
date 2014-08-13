#!/usr/bin/env python
# coding=utf8

from binascii import hexlify
from itsdangerous import TimestampSigner, BadData, URLSafeTimedSerializer


DAY = 60 * 60 * 24


class PasswordMixin(object):
    TOKEN_NONCE_SIZE = 5

    def get_context(self):
        return self.crypt_context

    def check_password(self, password):
        return self.get_context(self).verify(password, self._pwhash)

    def _create_signer(self, secret_key):
        return TimestampSigner(secret_key, self._pwhash, digest_method='hmac')

    def check_password_reset_token(self, secret_key, token, max_age_sec=DAY):
        signer = self._create_signer(secret_key)
        try:
            signer.unsign(token, max_age=max_age_sec)
            return True
        except BadData:
            return False

    def create_reset_password_token(self, secret_key):
        """Create a signed password reset token.

        A pasword reset token uses (secret_key + password_hash)
        as the signing key, causing it to stop working once the password
        has been altered. It also includes a creation timestamp.

        :param secret_key: The server's own secret key.
        :return: An urlsafe string.
        """

        # sign a few random bytes to hide repetitions
        signer = self._create_signer(secret_key)
        return signer.sign(hexlify(self.TOKEN_NONCE_SIZE))

    @property
    def password(self):
        raise TypeError(
            'password property is write-only, use check_password'
        )

    @password.setter
    def password(self, new_password):
        self._pwhash = self.get_context().encrypt(new_password)


class EmailMixin(object):
    def _create_serializer(self, secret_key):
        return URLSafeTimedSerializer(
            'devkey', self.email, signer_kwargs={'key_derivation': 'hmac'}
        )

    def activate_email(self, secret_key, token, max_age_sec=DAY):
        serializer = self._create_serializer(secret_key)
        try:
            return serializer.loads(token, max_age=max_age_sec)
        except BadData:
            return False

    def create_email_activation_token(self, secret_key, email):
        """Creates a new activation token that allows changing the email
        address from the previous address to the next one."""

        return self._create_serializer(secret_key).dumps(self.email)
