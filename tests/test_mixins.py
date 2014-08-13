#!/usr/bin/env python
# coding=utf8

import time

from alcohol.mixins import *
from alcohol.mixins.sqlalchemy import *
from passlib.context import CryptContext
import pytest
from six import b, byte2int, indexbytes


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


@pytest.fixture
def user_type(passlib_ctx):
    class User(PasswordMixin):
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    User.crypt_context = passlib_ctx
    return User


def tamper_with(bs):
    """Return len(bs)-variants of the bytestring bs, each with a different
    byte altered."""

    for i in range(0, len(bs)):
        if indexbytes(bs, i) != byte2int(b('0')):
            new_byte = b('0')
        else:
            new_byte = b('1')

        yield bs[:i] + new_byte + bs[i + 1:]


def test_password_check(user_type):
    valid_password = 's0m3p4$$w0rd'
    invalid_password = valid_password + 'x'
    user = user_type(password=valid_password)

    assert user.check_password(valid_password)
    assert not user.check_password(invalid_password)


def test_salted_passwords_are_not_equal(user_type, pw, secret_key):
    user = user_type(password=pw)
    user2 = user_type(password=pw)

    assert user._pwhash != user2._pwhash


def test_password_reset_tokens_are_different(user_type, pw, secret_key):
    user = user_type(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    assert token1 != token2


def test_password_reset_token_works(user_type, pw, secret_key):
    user = user_type(password=pw)
    token = user.create_reset_password_token(secret_key)

    assert user.check_password_reset_token(secret_key, token)


def test_password_reset_is_tamperproof(user_type, pw, secret_key):
    user = user_type(password=pw)
    token = user.create_reset_password_token(secret_key)

    for bad_token in tamper_with(token):
        assert not user.check_password_reset_token(secret_key, bad_token)


def test_password_reset_expires(user_type, pw, secret_key):
    user = user_type(password=pw)

    token = user.create_reset_password_token(secret_key)
    time.sleep(2)  # resolution in itsdangerous is 1 second

    assert not user.check_password_reset_token(
        secret_key, token, max_age_sec=1,  # checks for >
    )


def test_two_tokens_work_both(user_type, pw, secret_key):
    user = user_type(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    assert user.check_password_reset_token(secret_key, token2)
    assert user.check_password_reset_token(secret_key, token1)
    assert user.check_password_reset_token(secret_key, token2)


def test_tokens_stops_working_after_pw_change(user_type, pw, secret_key):
    user = user_type(password=pw)
    token1 = user.create_reset_password_token(secret_key)
    token2 = user.create_reset_password_token(secret_key)

    user.password = pw + pw

    assert not user.check_password_reset_token(secret_key, token2)
    assert not user.check_password_reset_token(secret_key, token1)


def test_password_cannot_be_read(user_type, pw, secret_key):
    user = user_type()

    with pytest.raises(TypeError):
        user.password
