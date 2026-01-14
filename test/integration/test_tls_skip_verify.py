import valkey

from util import LdapTestCase


class TlsSkipVerifyTest(LdapTestCase):
    """Test suite for ldap.tls_skip_verify configuration option"""

    def setUp(self):
        super(TlsSkipVerifyTest, self).setUp()
        
        # Configure for bind mode (simpler for testing)
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")
        self.vk.execute_command("CONFIG", "SET", "ldap.bind_dn_prefix", "cn=")
        self.vk.execute_command("CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io")

    def test_tls_skip_verify_can_be_enabled(self):
        """Test that tls_skip_verify can be set to yes"""
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "yes")
        result = self.vk.execute_command("CONFIG", "GET", "ldap.tls_skip_verify")
        self.assertEqual(result[1].decode("utf-8"), "yes")

    def test_tls_skip_verify_can_be_disabled(self):
        """Test that tls_skip_verify can be set to no"""
        # First enable it
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "yes")
        # Then disable it
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "no")
        result = self.vk.execute_command("CONFIG", "GET", "ldap.tls_skip_verify")
        self.assertEqual(result[1].decode("utf-8"), "no")

    def test_tls_skip_verify_with_ldaps(self):
        """Test that tls_skip_verify works with ldaps:// scheme"""
        # Enable tls_skip_verify (useful for self-signed certs in testing)
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "yes")
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        
        # This should work with self-signed certificates when skip_verify is enabled
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertEqual(resp.decode(), "user1")
        
        # Disable tls_skip_verify - should still work because we have CA cert configured
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "no")
        # Re-authenticate to test with new setting
        vk2 = valkey.Valkey(host="localhost", port=6379, db=0)
        vk2.execute_command("AUTH", "user1", "user1@123")
        resp = vk2.execute_command("ACL", "WHOAMI")
        self.assertEqual(resp.decode(), "user1")
        vk2.close()

    def test_tls_skip_verify_with_starttls(self):
        """Test that tls_skip_verify works with STARTTLS"""
        # Enable both tls_skip_verify and starttls
        self.vk.execute_command("CONFIG", "SET", "ldap.tls_skip_verify", "yes")
        self.vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "yes")
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap")
        
        # This should work with self-signed certificates when skip_verify is enabled
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertEqual(resp.decode(), "user1")
        
        # Reset starttls
        self.vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")
