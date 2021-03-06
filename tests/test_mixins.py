#!/usr/bin/env python
# coding=utf8

from datetime import timedelta, datetime
import time

from sqlalchemy import create_engine, Column, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.session import sessionmaker

from alcohol.mixins import EmailMixin, PasswordMixin
from alcohol.mixins.sqlalchemy import (SQLAlchemyEmailMixin,
                                       SQLAlchemyPasswordMixin, TimestampMixin)
from itsdangerous import want_bytes
from pytest_extra import group_fixture
from passlib.context import CryptContext
import pytest
from six import b, int2byte, indexbytes


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
def user_type_vanilla(passlib_ctx):
    class VanillaUserPw(KwargsBaseType, PasswordMixin, EmailMixin):
        email = None

    VanillaUserPw.crypt_context = passlib_ctx

    return VanillaUserPw


@pytest.fixture
def Base():
    return declarative_base()


@pytest.fixture
def user_type_sqlalchemy(passlib_ctx, Base):
    class SQLAlchemyUser(Base, SQLAlchemyEmailMixin, SQLAlchemyPasswordMixin):
        __tablename__ = 'users'
        id = Column(Integer(), primary_key=True)
        crypt_context = passlib_ctx

    return SQLAlchemyUser


@pytest.fixture
def engine():
    return create_engine('sqlite:///:memory:', echo=True)


@pytest.fixture
def db_schema(Base, engine):
    Base.metadata.create_all(bind=engine)


@pytest.fixture
def session(engine):
    Session = sessionmaker(bind=engine)
    return Session()


@group_fixture
def user_type():
    return ['user_type_vanilla', 'user_type_sqlalchemy']


@pytest.fixture
def email():
    return 'another@email.invalid'


@pytest.fixture
def gizmo_type(Base):
    class Gizmo(Base, TimestampMixin):
        __tablename__ = 'gizmos'
        id = Column(Integer, primary_key=True)

    return Gizmo


def tamper_with(bs):
    """Return len(bs)-variants of the bytestring bs, each with a different
    byte altered."""

    bs = want_bytes(bs)

    for i in range(0, len(bs)):
        new_byte = int2byte((indexbytes(bs, i) ^ 255) & 127  # stay in ascii range
                            )

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


def test_email_verification_token_works(user_type, secret_key, email):
    user = user_type()

    token = user.create_email_activation_token(secret_key, email)
    assert user.activate_email(secret_key, token)
    assert user.email == email


def test_email_verification_token_altered_fails(user_type, secret_key, email):
    user = user_type()

    token = user.create_email_activation_token(secret_key, email)

    for bad_token in tamper_with(token):
        assert not user.activate_email(secret_key, bad_token)
        assert user.email is None


def test_email_verification_token_usable_once(user_type, secret_key, email):
    user = user_type()

    token = user.create_email_activation_token(secret_key, email)
    assert user.activate_email(secret_key, token)
    assert not user.activate_email(secret_key, token)


def test_can_use_any_email_token(user_type, secret_key, email):
    user = user_type()

    # create some meaningless tokens
    user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)
    token = user.create_email_activation_token(secret_key, email)
    user.create_email_activation_token(secret_key, email)

    assert user.activate_email(secret_key, token)


@pytest.mark.usefixture('db_schema')
def test_stores_password(pw, user_type_sqlalchemy, session, db_schema):
    invalid_password = pw + 'x'

    user = user_type_sqlalchemy(password=pw)
    session.add(user)
    session.commit()

    user_id = user.id
    del user

    # retrieve
    user = session.query(user_type_sqlalchemy).get(user_id)

    assert user.check_password(pw)
    assert not user.check_password(invalid_password)


def test_timestamp_set_at_creation(gizmo_type, session, db_schema):
    g = gizmo_type()

    session.add(g)
    t = datetime.utcnow()
    session.commit()
    assert t - g.created < timedelta(seconds=1)
    assert g.modified is None


def test_timestamp_updated_on_update(gizmo_type, session, db_schema):
    g = gizmo_type()

    session.add(g)
    session.commit()

    time.sleep(1.1)

    created_before = g.created

    g.id = 99
    session.add(g)
    session.commit()

    t = datetime.utcnow()
    assert t - g.modified < timedelta(seconds=1)
    assert g.created == created_before


def test_last_modified(gizmo_type, session, db_schema):
    g = gizmo_type()
    session.add(g)
    session.commit()

    assert g.modified is None
    assert g.last_modified == g.created

    g.id = 99
    time.sleep(0.1)
    session.add(g)
    session.commit()

    assert g.created != g.modified
    assert g.last_modified == g.modified

    # check server-side expression is at least valid
    session.query(gizmo_type).filter(gizmo_type.last_modified != None).all()

    # FIXME: missing tests for NULL values and server-side tests
