import functools
import unittest
import hashlib, _hashlib, hmac



class HashlibFipsTests(unittest.TestCase):

    @unittest.skipUnless(_hashlib.get_fips_mode(), "Test only when FIPS is enabled")
    def test_fips_imports(self):
        """blake2s and blake2b should fail to import in FIPS mode
        """
        with self.assertRaises(ValueError, msg='blake2s not available in FIPS'):
            m = hashlib.blake2s()
        with self.assertRaises(ValueError, msg='blake2b not available in FIPS'):
            m = hashlib.blake2b()

    @unittest.skipUnless(_hashlib.get_fips_mode(), "Test only when FIPS is enabled")
    def test_hmac_no_python_fallback(self):
        """hmac must not fall back to its pure Python implementation in FIPS mode
        """
        # Callables other than _hashlib's own constructors and oversized keys
        # are handled by the pure Python fallback outside of FIPS mode.
        digestmod = functools.partial(hashlib.sha256)
        with self.assertRaises(ValueError):
            hmac.new(b'key', b'msg', digestmod)
        with self.assertRaises(ValueError):
            hmac.digest(b'key', b'msg', digestmod)
        with self.assertRaises(ValueError):
            hmac.digest(b'key', b'msg', 'md5')

    @unittest.skipIf(_hashlib.get_fips_mode(), "blake2 hashes are not available under FIPS")
    def test_blake2_hashes(self):
        self.assertEqual(hashlib.blake2b(b'abc').hexdigest(), _hashlib.openssl_blake2b(b'abc').hexdigest())
        self.assertEqual(hashlib.blake2s(b'abc').hexdigest(), _hashlib.openssl_blake2s(b'abc').hexdigest())


if __name__ == "__main__":
    unittest.main()
