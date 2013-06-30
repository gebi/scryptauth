scryptauth
==========

scryptauth is a GO library for secure password handling using scrypt

It uses `sha256_hmac(scrypt(user_password, salt), server_key)` to protect against
both dictionary attacks and DB leaks.

scryptauth additionally provides encode/decode routines using base64 to create strings
for storing into a DB.


Usage
-----

Choose your scrypt pw_cost factor (`make bench` helps you on this).
Typical values used in production are between 11 and 14 which means a login
will take at least 15 to 130ms, and your service will be able to handle only
66 and 8 logins per second with 100% load on a single CPU (keep that in mind!).


Documentation
-------------

http://godoc.org/github.com/gebi/scryptauth


Author
------

Michael Gebetsroither (michael \x40 mgeb \x2e org)


License
-------

BSD 2 clause
