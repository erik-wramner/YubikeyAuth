# YubikeyAuth
This code provides several examples of two-factor authentication with Yubikey
in Java EE. It is intended primarily for a talk on that subject, but can be
freely used (subject to The Apache Software License, Version 2.0, see
http://www.apache.org/licenses/LICENSE-2.0.txt) for other purposes.

Note that the code has been written to illustrate certain points for the
talk, so many parts are ***NOT*** production ready. You have been warned.

In order to run the examples you need to create a file in yubi-shared
in src/main/resources named yubico.properties with a client id and
secret key:

client_id=*****
secret_key=***************

Use https://upgrade.yubico.com/getapikey in order to get your own
client id and key.

You will also need to modify and run the UserAccountGenerator in the
same project in order to generate a file with users and passwords,
or strip out that code and read user data from a database or something.
Your call, but the current setup needs my Yubikey.

Most examples can be started with:

mvn jetty:run

The JASPIC example is started with:

mvn embedded-glassfish:run

Jetty has poor support for JASPIC.

NOTE! The examples are for Java SE 7. At least some of them will crash
and burn with Java SE 8. Don't blame me, blame Jetty or Glassfish.

As a final note the examples should be useful with Google Authenticator
or RSA ID or some other similar two factor implementation as well. They
are general enough to be useful for most two factor schemes.

Erik Wramner, CodeMint
http://www.codemint.com