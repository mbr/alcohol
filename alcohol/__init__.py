#!/usr/bin/env python
# coding=utf8

from blinker.base import Namespace

namespace = Namespace()

user_id_changed = namespace.signal('user_id_changed')
user_id_reset = namespace.namespace('user_id_reset')
