Password-based key derivation function 2 (PBKDF2)
=================================================
`PBKDF2 <http://en.wikipedia.org/wiki/PBKDF2>`_ is a key derivation function
that produces cryptographic keys from passwords and a number of parameters
(like salt, a number of iterations and a hash function).

The pbkdf2 included is a copy of `Armin Ronacher's excellent python-pbkdf2
<https://github.com/mitsuhiko/python-pbkdf2>`_, as it cannot be found on PyPI
otherwise. The module itself is very small, its documentation is found below.

Note that the mentioned function can also be found inside
`Werkzeug <http://werkzeug.pocoo.org>`_, as
:py:func:`werkzeug.security.safe_str_cmp`.

.. automodule:: alcohol.pbkdf2
