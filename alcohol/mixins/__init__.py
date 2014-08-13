#!/usr/bin/env python
# coding=utf8

import time


def password_mixin(get_token_gen=lambda obj: obj.token_gen,
                   get_context=lambda obj: obj.crypt_context):
    """Create a new :py:class:`~alcohol.mixins.PasswordMixin` class.

    :param get_token_gen: A function that given an object returns a token
                          generator instance. Defaults to the equivalent of
                          `getattr(obj, 'token_gen')`.
    :param get_context: Similiar to :py:func:`get_token_gen`, should return a
                        :py:class:`~passlib.context.CryptContext`.
    """
    class PasswordMixin(object):
        # fields:
        # self._pwhash
        def check_password(self, password):
            return get_context(self).verify(password, self._pwhash)

        def check_password_reset_token(self, token):
            return get_token_gen(self).check_token(
                token,
                bound_value=self._pwhash.encode('utf8')
            )

        def create_reset_password_token(self, valid_for=60 * 60 * 24):
            valid_until = int(time.time() + valid_for)
            return get_token_gen(self).generate_token(
                expires=valid_until,
                bound_value=self._pwhash.encode('utf8')
            )

        @property
        def password(self):
            raise TypeError(
                'password property is write-only, use check_password'
            )

        @password.setter
        def password(self, new_password):
            self._pwhash = get_context(self).encrypt(new_password)

    return PasswordMixin


def email_mixin(get_token_gen=lambda obj: obj.token_gen):
    """Create a new :py:class:`alcohol.mixins.EmailMixin` class.

    :param get_token_gen: A function that given an object returns a
                                     token generator instance. Defaults to the
                                     equivalent of `getattr(obj, 'token_gen')`.
    """
    class EmailMixin(object):
        def activate_email(self, token):
            if not get_token_gen(self).check_token(
                token,
                bound_value=self.unverified_email
            ):
                return False

            self.email = self.unverified_email
            self.unverified_email = None
            return True

        def create_email_activation_token(self, valid_for=60 * 60 * 24):
            if not getattr(self, 'unverified_email', None):
                raise AttributeError('No email set or email already verified')
            valid_until = int(time.time() + valid_for)
            return \
                get_token_gen(self).generate_token(
                    expires=valid_until,
                    bound_value=self.unverified_email
                )

    return EmailMixin
