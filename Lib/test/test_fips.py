import unittest
import hmac, _hmacopenssl
import hashlib, _hashlib



class HashlibFipsTests(unittest.TestCase):

    @unittest.skipUnless(_hashlib.get_fips_mode(), "Test only when FIPS is enabled")
    def test_fips_imports(self):
        """blake2s and blake2b should fail to import in FIPS mode
        """
        with self.assertRaises(ValueError, msg='blake2s not available in FIPS'):
            m = hashlib.blake2s()
        with self.assertRaises(ValueError, msg='blake2b not available in FIPS'):
            m = hashlib.blake2b()

    @unittest.skipIf(_hashlib.get_fips_mode(), "blake2 hashes are not available under FIPS")
    def test_blake2_hashes(self):
        self.assertEqual(hashlib.blake2b(b'abc').hexdigest(), _hashlib.openssl_blake2b(b'abc').hexdigest())
        self.assertEqual(hashlib.blake2s(b'abc').hexdigest(), _hashlib.openssl_blake2s(b'abc').hexdigest())

    def test_hmac_digests(self):
        self.assertEqual(_hmacopenssl.HMAC(b'My hovercraft is full of eels', digestmod='sha384').hexdigest(),
                            hmac.new(b'My hovercraft is full of eels', digestmod='sha384').hexdigest())




if __name__ == "__main__":
    unittest.main()
