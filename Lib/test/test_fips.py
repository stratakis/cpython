import unittest
import hmac, _hmacopenssl
import hashlib, _hashlib



class HashlibFipsTests(unittest.TestCase):

    def compare_hashes(self, python_hash, openssl_hash):
        """
        Compare between the python implementation and the openssl one that the digests
        are the same
        """
        if python_hash.name.startswith('shake_128'):
            m = python_hash.hexdigest(16)
        elif python_hash.name.startswith('shake_256'):
            m = python_hash.hexdigest(32)
        else:
            m = python_hash.hexdigest()
        h = openssl_hash.hexdigest()

        self.assertEqual(m, h)

    def test_sha(self):
        self.compare_hashes(hashlib.sha1(b'abc'), _hashlib.openssl_sha1(b'abc'))
        self.compare_hashes(hashlib.sha224(b'abc'), _hashlib.openssl_sha224(b'abc'))
        self.compare_hashes(hashlib.sha256(b'abc'), _hashlib.openssl_sha256(b'abc'))
        self.compare_hashes(hashlib.sha384(b'abc'), _hashlib.openssl_sha384(b'abc'))
        self.compare_hashes(hashlib.sha512(b'abc'), _hashlib.openssl_sha512(b'abc'))

    def test_hmac_digests(self):
        self.compare_hashes(_hmacopenssl.HMAC(b'My hovercraft is full of eels', digestmod='sha384'),
                            hmac.new(b'My hovercraft is full of eels', digestmod='sha384'))




if __name__ == "__main__":
    unittest.main()
