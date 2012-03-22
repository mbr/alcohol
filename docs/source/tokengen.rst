Token generation
================
The :py:mod:`alcohol.tokengen` module supports generating tokens for various
application. A typical usecase is generating a token for user that is then sent
to him via email and can be used to change his password.

The easiest approach is to generate a random value and send that but that has
the drawback of having to store the generated value as well. If the user
requests two "reset my password" emails in a short time (before the first one
arrives), he will be confused when the first one to arrive is already invalid.
Alternatively, you will have to store a lot of random values per user.

The token approach ties each token to a secret key. If a user requests a
password-reset token, you can use the password hash of his old password as the
secret key. This has numerous advantages:

  1. The token is only valid as long as the password has not been changed.
  2. There is no need to store anything extra in the database, as the token can
     be verified from the old password hash.
  3. Any number of tokens generated before remain valid until one of them is
     used.
  4. A secret key can be included as well to ensure that only tokens generated
     by the application itself are ever considered.

In addition to that, tokens can be outfitted with an expiration date. This
allows limiting the time that valid tokens can float around afterwards.

Finally, tokens are made to be reasonably long (storing salt and token data),
but not too long to cause problems with the user experience.

API documentation
-----------------

.. automodule:: alcohol.tokengen
   :members:
