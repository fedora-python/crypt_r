crypt_r --- Function to check Unix passwords
============================================

Originally by: Steven D. Majewski <sdm7g@virginia.edu>

The ``crypt_r`` module is a renamed copy of the ``crypt`` module
as it was present in Python 3.12 before it was removed.

See `PEP 594`_ for details of the removal.

Unlike ``crypt``, this library always exposes the `crypt_r(3)`_ function, not `crypt(3)`_.

Note that ``crypt_r`` is not part of any standard.
This library is tested with the ``crypt_r`` implementation in Fedora Linux
(libxcrypt, as of 2024), and should work with compatible implementations of ``crypt_r``
(such as ``libcrypt.so`` from older glibc).

Note that the improvements in ``crypt_r`` over ``crypt`` are in memory management and thread safety,
not security/cryptography.

It is easy to use ``crypt_r`` in an insecure way. Notably:
All hashing methods except ``METHOD_CRYPT`` (the original Unix algorithm from the 1970s)
are optional platform-specific extensions.
This library does not expose modern hashing methods like libxcrypt's yescrypt.
The last wrapper update is from 2017.
No future development is planned.

To use this module, you can either import ``crypt_r`` explicitly
or use the old ``crypt`` name for backward compatibility.
However, on Python older than 3.13, the ``crypt`` module
from the standard library will usually take precedence on ``sys.path``.

Here follows the original documentation for the removed ``crypt`` module,
updated to refer to it as ``crypt_r``:

--------------

This module implements an interface to the `crypt_r(3)`_ routine, which is
a one-way hash function based upon a modified DES algorithm; see the Unix man
page for further details.  Possible uses include storing hashed passwords
so you can check passwords without storing the actual password, or attempting
to crack Unix passwords with a dictionary.

Notice that the behavior of this module depends on the actual implementation  of
the `crypt_r(3)`_ routine in the running system.  Therefore, any
extensions available on the current implementation will also  be available on
this module.

Hashing Methods
---------------

New in Python 3.3.

The ``crypt_r`` module defines the list of hashing methods (not all methods
are available on all platforms):

``METHOD_SHA512``
   A Modular Crypt Format method with 16 character salt and 86 character
   hash based on the SHA-512 hash function.  This is the strongest method.

``METHOD_SHA256``
   Another Modular Crypt Format method with 16 character salt and 43
   character hash based on the SHA-256 hash function.

``METHOD_BLOWFISH``
   Another Modular Crypt Format method with 22 character salt and 31
   character hash based on the Blowfish cipher.

   New in Python 3.7.

``METHOD_MD5``
   Another Modular Crypt Format method with 8 character salt and 22
   character hash based on the MD5 hash function.

``METHOD_CRYPT``
   The traditional method with a 2 character salt and 13 characters of
   hash.  This is the weakest method.


Module Attributes
-----------------

New in Python 3.3.

``methods``
   A list of available password hashing algorithms, as
   ``crypt.METHOD_*`` objects.  This list is sorted from strongest to
   weakest.


Module Functions
----------------

The ``crypt_r`` module defines the following functions:

``crypt(word, salt=None)``
   *word* will usually be a user's password as typed at a prompt or  in a graphical
   interface.  The optional *salt* is either a string as returned from
   ``mksalt()``, one of the ``crypt.METHOD_*`` values (though not all
   may be available on all platforms), or a full encrypted password
   including salt, as returned by this function.  If *salt* is not
   provided, the strongest method available in ``methods`` will be used.

   Checking a password is usually done by passing the plain-text password
   as *word* and the full results of a previous  ``crypt``  call,
   which should be the same as the results of this call.

   *salt* (either a random 2 or 16 character string, possibly prefixed with
   ``$digit$`` to indicate the method) which will be used to perturb the
   encryption algorithm.  The characters in *salt* must be in the set
   ``[./a-zA-Z0-9]``, with the exception of Modular Crypt Format which
   prefixes a ``$digit$``.

   Returns the hashed password as a string, which will be composed of
   characters from the same alphabet as the salt.

   Since a few `crypt_r(3)`_ extensions allow different values, with
   different sizes in the *salt*, it is recommended to use  the full crypted
   password as salt when checking for a password.

   Changed in Python 3.3:
   Accept ``crypt.METHOD_*`` values in addition to strings for *salt*.


``mksalt(method=None, *, rounds=None)``
   Return a randomly generated salt of the specified method.  If no
   *method* is given, the strongest method available in ``methods`` is
   used.

   The return value is a string suitable for passing as the *salt* argument
   to  ``crypt`` .

   *rounds* specifies the number of rounds for ``METHOD_SHA256``,
   ``METHOD_SHA512`` and ``METHOD_BLOWFISH``.
   For ``METHOD_SHA256`` and ``METHOD_SHA512`` it must be an integer between
   ``1000`` and ``999_999_999``, the default is ``5000``.  For
   ``METHOD_BLOWFISH`` it must be a power of two between ``16`` (2\ :sup:`4`)
   and ``2_147_483_648`` (2\ :sup:`31`), the default is ``4096``
   (2\ :sup:`12`).

   New in Python 3.3.

   Changed in Python 3.7:
   Added the *rounds* parameter.


Examples
--------

A simple example illustrating typical use (a constant-time comparison
operation is needed to limit exposure to timing attacks.
`hmac.compare_digest()`_ is suitable for this purpose):

.. code-block:: python

   import pwd
   import crypt_r
   import getpass
   from hmac import compare_digest as compare_hash

   def login():
       username = input('Python login: ')
       cryptedpasswd = pwd.getpwnam(username)[1]
       if cryptedpasswd:
           if cryptedpasswd == 'x' or cryptedpasswd == '*':
               raise ValueError('no support for shadow passwords')
           cleartext = getpass.getpass()
           return compare_hash(crypt_r.crypt(cleartext, cryptedpasswd), cryptedpasswd)
       else:
           return True

To generate a hash of a password using the strongest available method and
check it against the original:

.. code-block:: python

   import crypt_r
   from hmac import compare_digest as compare_hash

   hashed = crypt_r.crypt(plaintext)
   if not compare_hash(hashed, crypt_r.crypt(plaintext, hashed)):
       raise ValueError("hashed version doesn't validate against original")

--------------


Changelog
---------

3.13.1
^^^^^^

* Fix build with ``-Werror=incompatible-pointer-types``


3.13.0
^^^^^^

* Initial fork from CPython 3.12.3
* Always uses the `crypt_r(3)`_ function, never `crypt(3)`_
* Renamed the Python modules to ``crypt_r`` and ``_crypt_r``

For historical changes when this module was included in Python,
please refer to the `Python 3.12 Changelog`_.


.. _PEP 594: https://peps.python.org/pep-0594/#crypt
.. _crypt(3): https://manpages.debian.org/crypt(3)
.. _crypt_r(3): https://manpages.debian.org/crypt_r(3)
.. _hmac.compare_digest(): https://docs.python.org/3/library/hmac.html#hmac.compare_digest
.. _Python 3.12 Changelog: https://docs.python.org/3.12/whatsnew/changelog.html
