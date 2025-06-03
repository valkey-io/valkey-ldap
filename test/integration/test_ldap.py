import time
from threading import Thread

from valkey.exceptions import AuthenticationError

from util import DOCKER_SERVICES, LdapTestCase, valkey_map_to_python_map


class LdapModuleTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )

    def test_ldap_module_unload_load(self):
        self.test_ldap_auth()
        self.vk.execute_command("MODULE", "UNLOAD", "ldap")
        self.vk.execute_command("MODULE", "LOAD", "./libvalkey_ldap.so")
        self.setUp()
        self.test_ldap_auth()

    def test_ldap_no_server_error(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "")
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "user1@123")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_wrong_pass(self):
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "wrongpass")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_tls_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "yes")
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_disabled(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "no")
        self.vk.execute_command("AUTH", "user1", "pass")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def test_ldap_failed_auth_but_locally_successfull(self):
        self.vk.execute_command("AUTH", "user1", "pass")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")


class LdapModuleBindAndSearchTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleBindAndSearchTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "search+bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")

        self.vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_ssl_auth(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")

    def test_ldap_auth_no_user(self):
        self.vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user2", "user2@123")

    def test_ldap_bind_password_hidden(self):
        res = self.vk.execute_command("CONFIG", "GET", "ldap.search_bind_passwd")
        self.assertEqual(res[1].decode("utf-8"), "*********")


class LdapModuleFailoverTest(LdapTestCase):
    def setUp(self):
        super(LdapModuleFailoverTest, self).setUp()

        DOCKER_SERVICES.assert_all_services_running()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "bind")

        self.vk.execute_command(
            "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
        )

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "user1", "user1@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "user1")

    def _wait_for_ldap_server_status(self, server_name, status_desc):
        while True:
            result = self.vk.execute_command("LDAP.STATUS")
            status = valkey_map_to_python_map(result)

            if status[server_name]["status"] == status_desc:
                return

            time.sleep(2)

    def test_single_auth_with_failover(self):
        service = DOCKER_SERVICES.stop_service("ldap")
        self._wait_for_ldap_server_status("ldap", "unhealthy")

        self.test_ldap_auth()

        DOCKER_SERVICES.restart_service(service)
        self._wait_for_ldap_server_status("ldap", "healthy")

    def test_single_auth_failure_and_recovery(self):
        service = DOCKER_SERVICES.stop_service("ldap")
        service2 = DOCKER_SERVICES.stop_service("ldap-2")
        self._wait_for_ldap_server_status("ldap", "unhealthy")
        self._wait_for_ldap_server_status("ldap-2", "unhealthy")

        with self.assertRaises(AuthenticationError) as ctx:
            self.vk.execute_command("AUTH", "user1", "user1@123")

        DOCKER_SERVICES.restart_service(service)
        self._wait_for_ldap_server_status("ldap", "healthy")

        self.test_ldap_auth()

        DOCKER_SERVICES.restart_service(service2)
        self._wait_for_ldap_server_status("ldap-2", "healthy")

    def test_multi_auth_with_failover(self):
        stop_worker = False
        worker_result = {"success": True, "error": None}

        def auth_worker():
            try:
                while not stop_worker:
                    self.test_ldap_auth()
            except Exception as ex:
                worker_result["success"] = False
                worker_result["error"] = ex

        worker_thread = Thread(target=auth_worker)
        worker_thread.start()
        time.sleep(1)

        service = DOCKER_SERVICES.stop_service("ldap")
        self._wait_for_ldap_server_status("ldap", "unhealthy")
        time.sleep(1)
        DOCKER_SERVICES.restart_service(service)
        self._wait_for_ldap_server_status("ldap", "healthy")

        stop_worker = True
        worker_thread.join()

        self.assertIsNone(worker_result["error"])


class LdapModuleSearchAndBindFailoverTest(LdapModuleFailoverTest):
    def setUp(self):
        super(LdapModuleSearchAndBindFailoverTest, self).setUp()

        self.vk.execute_command("CONFIG", "SET", "ldap.auth_mode", "search+bind")

        self.vk.execute_command("CONFIG", "SET", "ldap.search_base", "dc=valkey,dc=io")
        self.vk.execute_command(
            "CONFIG", "SET", "ldap.search_bind_dn", "cn=admin,dc=valkey,dc=io"
        )
        self.vk.execute_command("CONFIG", "SET", "ldap.search_bind_passwd", "admin123!")

    def test_ldap_auth(self):
        self.vk.execute_command("AUTH", "u2", "user2@123")
        resp = self.vk.execute_command("ACL", "WHOAMI")
        self.assertTrue(resp.decode() == "u2")
