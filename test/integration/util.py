from unittest import TestCase
import docker
import valkey

class DockerServices:

    def __init__(self):
        self.client = docker.from_env()

    def assert_all_services_running(self):
        for ct in self.client.containers.list():
            assert(ct.status == "running")

    def _find_container(self, name):
        for ct in self.client.containers.list():
            if ct.name == name:
                return ct
        return None

    def stop_service(self, name):
        ct = self._find_container(name)
        ct.kill()
        return ct

    def restart_service(self, serv):
        serv.restart()


DOCKER_SERVICES = DockerServices()


class LdapTestCase(TestCase):
    def setUp(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)

        vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "yes")

        # LDAP server location
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap ldap://ldap-2")

        # TLS configuration
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt"
        )
        vk.execute_command(
            "CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key"
        )
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")

        # Add users in Valkey
        vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")
        vk.execute_command("ACL", "SETUSER", "u2", "ON", ">pass", "allcommands")

        self.vk = vk

    def tearDown(self):
        self.vk.close()
        self.vk = None


def valkey_map_to_python_map(valkey_map):
    def _to_python_value(vk_value):
        if isinstance(vk_value, list):
            return valkey_map_to_python_map(vk_value)
        else:
            return vk_value.decode('utf-8')

    python_map = {}
    for i in range(0, len(valkey_map), 2) :
        python_map[valkey_map[i].decode('utf-8')] = _to_python_value(valkey_map[i + 1])

    return python_map
