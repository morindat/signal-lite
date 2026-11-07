"""Command-line entry points: the relay and the chat client.

    python -m signallite.cli server --port 8765
    python -m signallite.cli client --user alice
    python -m signallite.cli client --user bob
"""

from __future__ import annotations

import argparse
import sys
import threading
from pathlib import Path

from .account import Account
from .client import Client, ClientError
from .server import create_server

DEFAULT_SERVER = "http://127.0.0.1:8765"
DEFAULT_STATE_DIR = "state"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signal-lite",
        description="Educational Signal-style end-to-end encrypted chat.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser(
        "server", help="run the untrusted relay"
    )
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8765)
    server_parser.add_argument(
        "--verbose", action="store_true", help="log every HTTP request"
    )

    client_parser = subparsers.add_parser(
        "client", help="run an interactive chat client"
    )
    client_parser.add_argument("--user", required=True)
    client_parser.add_argument("--device", default="default")
    client_parser.add_argument("--server", default=DEFAULT_SERVER)
    client_parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    client_parser.add_argument(
        "--opks",
        type=int,
        default=20,
        help="number of one-time prekeys to generate on first run",
    )
    client_parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="seconds between inbox polls",
    )
    return parser


def run_server(args: argparse.Namespace) -> int:
    server = create_server(args.host, args.port, verbose=args.verbose)
    host, port = server.server_address[:2]
    print(f"signal-lite relay listening on http://{host}:{port}", flush=True)
    print("press Ctrl+C to stop", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nrelay stopped", flush=True)
    finally:
        server.server_close()
    return 0


def run_client(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    state_path = state_dir / f"{args.user}.json"
    if state_path.exists():
        account = Account.load(state_path)
    else:
        account = Account.create(args.user, args.device, num_opks=args.opks)
        account.save(state_path)

    client = Client(account, args.server, state_path)
    try:
        client.register()
    except ClientError as exc:
        print(f"could not register with the relay: {exc}", file=sys.stderr)
        return 1

    print(f"signal-lite | {account.user}@{account.device}", flush=True)
    print(f"relay      | {client.server_url}", flush=True)
    print(f"identity   | {client.own_fingerprint()}", flush=True)
    print(
        "commands   | /to <user>  /users  /fingerprint [user]  /help  /quit",
        flush=True,
    )

    stop = threading.Event()

    def poll_loop() -> None:
        while not stop.is_set():
            try:
                for peer, text in client.receive_all():
                    print(f"\n[{peer}] {text}", flush=True)
            except Exception as exc:  # keep the chat alive
                print(f"\n[relay error] {exc}", flush=True)
            print_events(client)
            stop.wait(args.poll_interval)

    poller = threading.Thread(target=poll_loop, daemon=True)
    poller.start()

    peer: str | None = None
    try:
        while True:
            prompt = f"[{peer}] > " if peer else "> "
            try:
                line = input(prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            line = line.strip()
            if not line:
                continue
            if line in ("/quit", "/exit"):
                break
            if line == "/help":
                print_help()
                continue
            if line == "/users":
                try:
                    print("users:", ", ".join(client.list_users()))
                except Exception as exc:
                    print(f"[error] {exc}")
                continue
            if line in ("/fingerprint", "/fp"):
                print("your fingerprint:", client.own_fingerprint())
                continue
            if line.startswith("/fingerprint ") or line.startswith("/fp "):
                target = line.split(maxsplit=1)[1].strip()
                try:
                    print(
                        f"safety number with {target}: "
                        f"{client.safety_number(target)}"
                    )
                except Exception as exc:
                    print(f"[error] {exc}")
                continue
            if line.startswith("/to "):
                peer = line.split(maxsplit=1)[1].strip()
                if peer == account.user:
                    print("you cannot message yourself in this demo")
                    peer = None
                else:
                    print(f"recipient set to {peer}")
                continue
            if line.startswith("/"):
                print("unknown command; try /help")
                continue
            if peer is None:
                print("set a recipient first: /to <user>")
                continue
            try:
                client.send(peer, line)
                print(f"[you -> {peer}] {line}")
            except Exception as exc:
                print(f"[send failed] {exc}")
            print_events(client)
    finally:
        stop.set()
        poller.join(timeout=2)
        client.save()
    return 0


def print_events(client: Client) -> None:
    for event in client.drain_events():
        kind = event[0]
        if kind == "identity_changed":
            _, peer, old, new = event
            print(
                "\n!! SECURITY WARNING: the identity key for "
                f"{peer} changed !!\n"
                f"   old: {old}\n"
                f"   new: {new}\n"
                "   This is what a reinstall looks like, but it is also what a "
                "server MITM looks like.\n"
                "   Compare safety numbers out of band before trusting it.",
                flush=True,
            )
        elif kind == "decrypt_error":
            _, peer, error = event
            print(f"\n[decrypt error from {peer}] {error}", flush=True)


def print_help() -> None:
    print(
        "\n".join(
            [
                "commands:",
                "  /to <user>          set the current recipient",
                "  /users              list registered users",
                "  /fingerprint        show your identity fingerprint",
                "  /fingerprint <user> show the pairwise safety number",
                "  /help               show this help",
                "  /quit               exit",
                "anything else is sent as a message to the current recipient",
            ]
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "server":
        return run_server(args)
    if args.command == "client":
        return run_client(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
