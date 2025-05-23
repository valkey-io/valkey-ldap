import sys
import valkey
from threading import Thread
from datetime import datetime


class Worker(Thread):
    def __init__(self, tid, num_requests):
        super(Worker, self).__init__()
        self.tid = tid
        self.num_requests = num_requests
        self.latencies = []
        self.duration = None

    def run(self):
        vk = valkey.Valkey(host="localhost", port=6379, db=0)
        i = 0
        begin_ts = datetime.now()
        while i < self.num_requests:
            i += 1
            st = datetime.now()
            vk.execute_command("AUTH", "user1", "user1@123")
            et = datetime.now()
            self.latencies.append((et - st).total_seconds())

        end_ts = datetime.now()

        self.duration = round((end_ts - begin_ts).total_seconds(), 3)

    def average_latency(self):
        sum_lat = sum(self.latencies)
        return round(sum_lat / len(self.latencies), 3)

    def print_stats(self):

        print(
            f"[{self.tid}: total={self.num_requests} duration(s)={self.duration} throughput(req/sec)={int(self.num_requests/self.duration)} avg_latency(s)={self.average_latency()}]"
        )


USAGE_STR = "Usage: python auth_requests.py [-(ldaps|starttls)] [-p<connection_pool_size>] -n<num_auth_requests> -w<num_workers>"


def main():
    if len(sys.argv) < 3:
        print()
        exit(1)

    num_requests = None
    num_workers = None
    use_ldaps = False
    use_starttls = False
    connection_pool_size = None

    for arg in sys.argv[1:]:
        if arg.startswith("-n"):
            num_requests = int(arg[2:])
        elif arg.startswith("-w"):
            num_workers = int(arg[2:])
        elif arg == "-ldaps":
            use_ldaps = True
        elif arg == "-starttls":
            use_starttls = True
        elif arg.startswith("-p"):
            connection_pool_size = int(arg[2:])
        else:
            print(f"Error: invalid option {arg}")
            print(USAGE_STR)
            exit(1)

    if num_requests is None or num_workers is None:
        print("Error: <num_auth_requests> and <num_workers> was not specified")
        print(USAGE_STR)
        exit(1)

    if use_ldaps and use_starttls:
        print("Error: -ldaps and -starttls are exclusive options")
        print(USAGE_STR)
        exit(1)

    vk = valkey.Valkey(host="localhost", port=6379, db=0)

    vk.execute_command("CONFIG", "SET", "ldap.auth_enabled", "yes")
    if use_ldaps:
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldaps://ldap")
    else:
        vk.execute_command("CONFIG", "SET", "ldap.servers", "ldap://ldap")

    if use_starttls:
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "yes")
    else:
        vk.execute_command("CONFIG", "SET", "ldap.use_starttls", "no")

    if connection_pool_size is not None:
        vk.execute_command("CONFIG", "SET", "ldap.connection_pool_size", f"{connection_pool_size}")

    vk.execute_command(
        "CONFIG", "SET", "ldap.tls_ca_cert_path", "/valkey-ldap/valkey-ldap-ca.crt"
    )
    vk.execute_command(
        "CONFIG", "SET", "ldap.tls_cert_path", "/valkey-ldap/valkey-ldap-client.crt"
    )
    vk.execute_command(
        "CONFIG", "SET", "ldap.tls_key_path", "/valkey-ldap/valkey-ldap-client.key"
    )

    vk.execute_command(
        "CONFIG", "SET", "ldap.bind_dn_suffix", ",OU=devops,DC=valkey,DC=io"
    )

    vk.execute_command("ACL", "SETUSER", "user1", "ON", ">pass", "allcommands")

    workers = []
    for i in range(num_workers):
        workers.append(Worker(i + 1, num_requests))

    begin_ts = datetime.now()
    for worker in workers:
        worker.start()

    for worker in workers:
        worker.join()
        worker.print_stats()

    end_ts = datetime.now()

    duration = round((end_ts - begin_ts).total_seconds(), 3)
    total_requests = num_requests * num_workers

    print()
    print(
        f"total={total_requests} duration(s)={duration} throughput(req/sec)={int(total_requests/duration)}"
    )

    vk.close()


if __name__ == "__main__":
    main()
