#!/usr/bin/env python
# coding=utf8

from google.appengine.ext import ndb

def ndb_password_mixin(indexed_hashes=False, **kwargs):
    MixinBase = password_mixin(**kwargs)

    class AppEngineNdbMixin(MixinBase):
        _pwhash = ndb.StringProperty(indexed=indexed_hashes)

    return AppEngineNdbMixin


def ndb_email_mixin(**kwargs):
    MixinBase = email_mixin(**kwargs)

    class AppEngineEmailMixin(MixinBase):
        email = ndb.StringProperty()
        unverified_email = ndb.StringProperty()

    return AppEngineEmailMixin
