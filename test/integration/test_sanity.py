from unittest import TestCase

import valkey

class SanityTest(TestCase):
    def test_always_passes(self):
        self.assertTrue(True)

    def test_ping_server(self):
        vk = valkey.Valkey(host='localhost', port=6379, db=0)
        resp = vk.ping()
        self.assertTrue(resp)