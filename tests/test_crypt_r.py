import sys
import unittest

import crypt_r


class CryptRTestCase(unittest.TestCase):
    crypt = crypt_r

    def test_crypt(self):
        cr = self.crypt.crypt('mypassword')
        cr2 = self.crypt.crypt('mypassword', cr)
        self.assertEqual(cr2, cr)
        cr = self.crypt.crypt('mypassword', 'ab')
        if cr is not None:
            cr2 = self.crypt.crypt('mypassword', cr)
            self.assertEqual(cr2, cr)

    def test_salt(self):
        self.assertEqual(len(self.crypt._saltchars), 64)
        for method in self.crypt.methods:
            salt = self.crypt.mksalt(method)
            self.assertIn(len(salt) - method.salt_chars, {0, 1, 3, 4, 6, 7})
            if method.ident:
                self.assertIn(method.ident, salt[:len(salt)-method.salt_chars])

    def test_saltedcrypt(self):
        for method in self.crypt.methods:
            cr = self.crypt.crypt('assword', method)
            self.assertEqual(len(cr), method.total_size)
            cr2 = self.crypt.crypt('assword', cr)
            self.assertEqual(cr2, cr)
            cr = self.crypt.crypt('assword', self.crypt.mksalt(method))
            self.assertEqual(len(cr), method.total_size)

    def test_methods(self):
        self.assertTrue(len(self.crypt.methods) >= 1)
        if sys.platform.startswith('openbsd'):
            self.assertEqual(self.crypt.methods, [self.crypt.METHOD_BLOWFISH])
        else:
            self.assertEqual(self.crypt.methods[-1], self.crypt.METHOD_CRYPT)

    @unittest.skipUnless(
        crypt.METHOD_SHA256 in crypt.methods or crypt.METHOD_SHA512 in crypt.methods,
        'requires support of SHA-2',
    )
    def test_sha2_rounds(self):
        for method in (self.crypt.METHOD_SHA256, self.crypt.METHOD_SHA512):
            for rounds in 1000, 10_000, 100_000:
                salt = self.crypt.mksalt(method, rounds=rounds)
                self.assertIn('$rounds=%d$' % rounds, salt)
                self.assertEqual(len(salt) - method.salt_chars,
                                 11 + len(str(rounds)))
                cr = self.crypt.crypt('mypassword', salt)
                self.assertTrue(cr)
                cr2 = self.crypt.crypt('mypassword', cr)
                self.assertEqual(cr2, cr)

    @unittest.skipUnless(
        crypt.METHOD_BLOWFISH in crypt.methods, 'requires support of Blowfish'
    )
    def test_blowfish_rounds(self):
        for log_rounds in range(4, 11):
            salt = self.crypt.mksalt(self.crypt.METHOD_BLOWFISH, rounds=1 << log_rounds)
            self.assertIn('$%02d$' % log_rounds, salt)
            self.assertIn(len(salt) - self.crypt.METHOD_BLOWFISH.salt_chars, {6, 7})
            cr = self.crypt.crypt('mypassword', salt)
            self.assertTrue(cr)
            cr2 = self.crypt.crypt('mypassword', cr)
            self.assertEqual(cr2, cr)

    @unittest.skipUnless(
        crypt_r.METHOD_YESCRYPT in crypt_r.methods, 'requires support of yescrypt'
    )
    def test_yescrypt(self):
        # Adding yescrypt must not change the default method.
        self.assertNotEqual(self.crypt.methods[0], self.crypt.METHOD_YESCRYPT)
        # Arbitrary characters from _saltchars are not a valid yescrypt salt,
        # so every generated one must be accepted, not just most of them.
        salts = {self.crypt.mksalt(self.crypt.METHOD_YESCRYPT) for _ in range(20)}
        self.assertEqual(len(salts), 20)
        for salt in salts:
            cr = self.crypt.crypt('mypassword', salt)
            self.assertEqual(len(cr), self.crypt.METHOD_YESCRYPT.total_size)
            self.assertTrue(cr.startswith(salt + '$'))
            self.assertEqual(self.crypt.crypt('mypassword', cr), cr)
        cr = self.crypt.crypt('mypassword', self.crypt.METHOD_YESCRYPT)
        self.assertNotEqual(self.crypt.crypt('wrongpassword', cr), cr)

    @unittest.skipUnless(
        crypt_r.METHOD_YESCRYPT in crypt_r.methods, 'requires support of yescrypt'
    )
    def test_yescrypt_rounds(self):
        params = set()
        for rounds in range(1, 6):
            salt = self.crypt.mksalt(self.crypt.METHOD_YESCRYPT, rounds=rounds)
            self.assertTrue(salt.startswith('$y$'))
            params.add(salt[:-self.crypt.METHOD_YESCRYPT.salt_chars])
            cr = self.crypt.crypt('mypassword', salt)
            self.assertTrue(cr.startswith(salt + '$'))
            self.assertEqual(self.crypt.crypt('mypassword', cr), cr)
        self.assertEqual(len(params), 5)

    def test_invalid_rounds(self):
        with self.assertRaises(TypeError):
            self.crypt.mksalt(self.crypt.METHOD_YESCRYPT, rounds='5')
        for rounds in (0, 12, -1, 1<<999):
            with self.assertRaises(ValueError):
                self.crypt.mksalt(self.crypt.METHOD_YESCRYPT, rounds=rounds)
        for method in (self.crypt.METHOD_SHA256, self.crypt.METHOD_SHA512,
                       self.crypt.METHOD_BLOWFISH):
            with self.assertRaises(TypeError):
                self.crypt.mksalt(method, rounds='4096')
            with self.assertRaises(TypeError):
                self.crypt.mksalt(method, rounds=4096.0)
            for rounds in (0, 1, -1, 1<<999):
                with self.assertRaises(ValueError):
                    self.crypt.mksalt(method, rounds=rounds)
        with self.assertRaises(ValueError):
            self.crypt.mksalt(self.crypt.METHOD_BLOWFISH, rounds=1000)
        for method in (self.crypt.METHOD_CRYPT, self.crypt.METHOD_MD5):
            with self.assertRaisesRegex(ValueError, 'support'):
                self.crypt.mksalt(method, rounds=4096)


if sys.version_info >= (3, 13):
    import crypt

    class CryptTestCase(CryptRTestCase):
        crypt = crypt


if __name__ == "__main__":
    unittest.main()
