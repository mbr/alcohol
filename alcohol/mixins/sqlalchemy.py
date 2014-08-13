#!/usr/bin/env python
# coding=utf8

from __future__ import absolute_import
from datetime import datetime
from sqlalchemy import Column, String, Unicode, DateTime
from . import PasswordMixin, EmailMixin


class SQLAlchemyPasswordMixin(PasswordMixin):
    HASH_FIELD_LEN = 511
    _pwhash = Column(String(HASH_FIELD_LEN))


class SQLAlchemyEmailMixin(EmailMixin):
    MAX_EMAIL_LENGTH = 1023
    email = Column(Unicode(MAX_EMAIL_LENGTH))


class TimestampMixin(object):
    created = Column(DateTime, default=datetime.utcnow, nullable=False)
    modified = Column(DateTime, onupdate=datetime.utcnow)
