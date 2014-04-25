Natrium
=======

Natrium is an easy-to-use .NET wrapper for [libsodium](https://github.com/jedisct1/libsodium). Libsodium itself is a new, highly secure cryptographic library based on algorithms used in [NaCl](http://nacl.cr.yp.to/).

Natrium makes it possible to implement _secure_ cryptography into your .NET applications using carefully selected algorithms chosen by cryptographic experts. The following excerpt is from libsodium web page:
```
The design choices, particularly in regard to the Curve25519 Diffie-Hellman function, emphasize security (whereas NIST curves emphasize "performance" at the cost of security), and "magic constants" in NaCl/Sodium have clear rationales.

The same cannot be said of NIST curves, where the specific origins of certain constants are not described by the standards.

And despite the emphasis on higher security, primitives are faster across-the-board than most implementations of the NIST standards.
```

## Usage

In order to use Natrium, you must build the VS solution to get Natrium.dll. When the build is done, you can reference Natrium.dll from your .NET project and start using the classes it contains. Remember to copy the files 'libsodium-32.dll' and 'libsodium-64.dll' from the Deps directory into same directory with your .NET executable files to make them available for Natrium to load.

### License

Natrium is licensed under MIT license. Check the included file LICENSE.md for more details on how the included third-party libraries are licensed.