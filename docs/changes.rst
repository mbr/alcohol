API Changes
===========

0.4
---
* Removed ``tokengen`` module, its functionality being replaced
  by :py:mod:`itsdangerous`.
* The :ref:`authorization` module has been added.
* Dropped Google App Engine support.

0.3
---
* The `expires` parameter on :py:attr:`~alcohol.user_id_changed` has been
  replaced with an `expire_on` parameter.
* The ``tokengen`` has had API changes, which are only
  relevant if you used it with non-default settings.
* The :py:mod:`~alcohol.mixins` modules has seen a thorough refactoring,
  causing its API to change.
* The formerly availble `pbkdf2` and `safe_str_cmp` modules have disappeared,
  in favor of :py:mod:`passlib.utils`.
