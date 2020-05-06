/* Call the _HASH macro with all the hashes exported by OpenSSL,
 * at compile time.
 *
 * This file is meant to be included multiple times, with different values of
 * _HASH.
 */

_HASH(md5, "md5")
_HASH(sha1, "sha1")
_HASH(sha224, "sha224")
_HASH(sha256, "sha256")
_HASH(sha384, "sha384")
_HASH(sha512, "sha512")
