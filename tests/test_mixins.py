#!/usr/bin/env python
# coding=utf8

import time

from alcohol.mixins import *
from alcohol.mixins.sqlalchemy import *
from passlib.context import CryptContext
import pytest
from six import b, int2byte, indexbytes

from itsdangerous import want_bytes


@pytest.fixture
def scheme():
    return "sha256_crypt"


@pytest.fixture(params=['testkey', b('testkey')])
def secret_key(request):
    return request.param


@pytest.fixture
def passlib_ctx(scheme):
    return CryptContext(schemes=[scheme])


@pytest.fixture
def pw():
    return 'foobartestpw'


class KwargsBaseType(object):
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture
def user_type_pw(passlib_ctx):
    class User(KwargsBaseType, PasswordMixin):
        pass

    User.crypt_context = passlib_ctx
    return User


@pytest.fixture
def user_type_ml():
    class User(EmailMixin):
        email = None

    return User


@pytest.fixture
def email():
    return 'another@email.invalid'


def tamper_with(bs):
    """Return len(bs)-variants of the bytestring bs, each with a different
    byte altered."""

    bs = want_bytes(bs)

    for i in range(0, len(bs)):
        new_byte = int2byte(
            (indexbytes(bs, i) ^ 255) & 127  # stay in ascii range
        )

        yield bs[:i] + new_byte + bs[i + 1:]


def test_password_check(user_type_pw):
    valid_password = 's0m3p4$$w0rd'
    invalid_password = valid_password + 'x'
    user = user_type_pw(password=valid_password)

    assert user.check_password(valid_password)
    assert not user.check_password(invalid_password)


def test_salted_passwords_are_not_equal(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    user2 = user_type_pw(password=pw)

    assert user._pwhash != user2._pwhash


def test_password_reset_tokens_are_different(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    assert token1 != token2


def test_password_reset_token_works(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    token = user.create_reset_password_token(secret_key)

    assert user.check_password_reset_token(secret_key, token)


def test_password_reset_is_tamperproof(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    token = user.create_reset_password_token(secret_key)

    for bad_token in tamper_with(token):
        assert not user.check_password_reset_token(secret_key, bad_token)


def test_password_reset_expires(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)

    token = user.create_reset_password_token(secret_key)
    time.sleep(2)  # resolution in itsdangerous is 1 second

    assert not user.check_password_reset_token(
        secret_key, token, max_age_sec=1,  # checks for >
    )


def test_two_tokens_work_both(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    assert user.check_password_reset_token(secret_key, token2)
    assert user.check_password_reset_token(secret_key, token1)
    assert user.check_password_reset_token(secret_key, token2)


def test_tokens_stops_working_after_pw_change(user_type_pw, pw, secret_key):
    user = user_type_pw(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    user.password = pw + pw

    assert not user.check_password_reset_token(secret_key, token2)
    assert not user.check_password_reset_token(secret_key, token1)


def test_password_cannot_be_read(user_type_pw, pw, secret_key):
    user = user_type_pw()

    with pytest.raises(TypeError):
        user.password


def test_email_verification_token_works(user_type_ml, secret_key, email):
    user = user_type_ml()

    token = user.create_email_activation_token(secret_key, email)
    assert user.activate_email(secret_key, token)
    assert user.email == email


def test_email_verification_token_altered_fails(
    user_type_ml, secret_key, email
):
    user = user_type_ml()

    token = user.create_email_activation_token(secret_key, email)

    for bad_token in tamper_with(token):
        assert not user.activate_email(secret_key, bad_token)
        assert user.email is None


def test_email_verification_token_usable_once(user_type_ml, secret_key, email):
    user = user_type_ml()

    token = user.create_email_activation_token(secret_key, email)
    assert user.activate_email(secret_key, token)
    assert not user.activate_email(secret_key, token)


def test_can_use_any_email_token(user_type_ml, secret_key, email):
    user = user_type_ml()

    # create some meaningless tokens
    user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)
    token = user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)

    assert user.activate_email(secret_key, token)
