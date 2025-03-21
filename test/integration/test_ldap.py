from unittest import TestCase

import valkey

class LdapModuleTest(TestCase):
    def test_ldap_auth(self):
        vk = valkey.Valkey(host='localhost', port=6379, db=0)
        resp = vk.execute_command("LDAP.TEST_AUTH", "user1", "user1@123")
        self.assertTrue(resp)
