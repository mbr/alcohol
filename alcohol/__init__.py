#!/usr/bin/env python
# coding=utf8

from blinker.base import Namespace, Signal

namespace = Namespace()

user_id_changed = namespace.signal('user_id_changed')
user_id_reset = namespace.signal('user_id_reset')
user_changed = namespace.signal('user_changed')

user_id_required = namespace.signal('user_id_required')
