#!/usr/bin/env python
# coding=utf8

from __future__ import absolute_import
from datetime import datetime
from sqlalchemy import Column, String, Unicode, DateTime
from . import PasswordMixin, EmailMixin


class SQLAlchemyPasswordMixin(PasswordMixin):
    """Adds a :class:`~sqlalchemy.types.String`
    :class:`~sqlalchemy.schema.Column` containing the password hash.

    Supports the same interface as :class:`~alcohol.mixins.PasswordMixin`."""
    HASH_FIELD_LEN = 511
    _pwhash = Column(String(HASH_FIELD_LEN))


class SQLAlchemyEmailMixin(EmailMixin):
    """Adds a :class:`~sqlalchemy.types.Unicode`
    :class:`~sqlalchemy.schema.Column` named ``email`` for storing a users
    email address.

    Supports the same interface as :class:`~alcohol.mixins.EmailMixin`."""
    MAX_EMAIL_LENGTH = 1023
    email = Column(Unicode(MAX_EMAIL_LENGTH))


class TimestampMixin(object):
    """A mixin that adds two timestamp fields, `created` and `modified`. The
    `created` timestamp is updated only on creation, while every SQL UPDATE
    will trigger a refresh of the `modified` timestamp."""

    created = Column(DateTime, default=datetime.utcnow, nullable=False)
    """A :py:class:`datetime.datetime` instance containing the time this record
    was created."""

    modified = Column(DateTime, onupdate=datetime.utcnow)
    """A :py:class:`datetime.datetime` instance containing the time this record
    was last modified."""
