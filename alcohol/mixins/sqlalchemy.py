#!/usr/bin/env python
# coding=utf8

from __future__ import absolute_import
from datetime import datetime, timedelta
from sqlalchemy import Column, String, Unicode, DateTime, func
from . import password_mixin


def sqlalchemy_password_mixin(max_hash_size=500, **kwargs):
    MixinBase = password_mixin(**kwargs)

    class SqlAlchemyPasswordMixin(MixinBase):
        _pwhash = Column(String(max_hash_size))

    return SqlAlchemyPasswordMixin


def sqlalchemy_email_mixin(max_email_length=1024, **kwargs):
    MixinBase = email_mixin(**kwargs)

    class SqlAlchemyEmailMixin(MixinBase):
        email = Column(Unicode(max_email_length))
        unverified_email = Column(Unicode(max_email_length))

    return SqlAlchemyEmailMixin


def sqlalchemy_timestamp_mixin(use_serverside_now=True):
    """Create a new :py:class:`alcohol.mixins.sqlalchemy.TimestampMixin` class.

    :param use_serverside_now: Whether to use an SQL NOW() function or add a
                               client-side default-value of
                               :py:attr:`datetime.datetime.now`.
    :return: A class suitable for mixing into any SQLAlchemy model object.
    """
    if use_serverside_now:
        class TimestampMixin(object):
            created = Column(DateTime, default=datetime.utcnow, nullable=False)
            modified = Column(DateTime, onupdate=datetime.utcnow)
    else:
        class TimestampMixin(object):
            created = Column(DateTime, server_default=func.now(),
                             nullable=False)
            modified = Column(DateTime, onupdate=func.now())

    return TimestampMixin
