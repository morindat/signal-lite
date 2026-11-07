import threading

import pytest

from signallite.account import Account
from signallite.client import Client
from signallite.server import create_server


@pytest.fixture
def relay():
    server = create_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def client_factory(tmp_path, relay):
    def make(user: str, num_opks: int = 5) -> Client:
        account = Account.create(user, "default", num_opks=num_opks)
        client = Client(account, relay, tmp_path / f"{user}.json")
        client.register()
        return client

    return make
