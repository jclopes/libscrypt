# libscrypt
A pure c# implementation of scrypt with no dependencies on crypto libraries.
Inclues implementations of SHA256 and PBKDF2.

## Motivation
I build this to develop mobile apps that use scrypt. For some reason xamarin c# runtimes for android and iOS don't include crypto libs or these libs are very limited/broken.

## Disclaimer
I'm not a security expert and my implementation of these algorithms might be vulnerable to attacks.
Don't use this on security critical systems.
