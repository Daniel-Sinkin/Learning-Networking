"""client.py"""

from pathlib import Path
import socket


def load_port(dotenv: Path = Path(".env")) -> int:
    if not dotenv.exists():
        print(f"Warning: {dotenv} not found, falling back to 12345")
        return 12345
    for line in dotenv.read_text(encoding="utf8").splitlines():
        if "=" not in line:
            continue
        key, value = (part.strip().strip('"') for part in line.split("=", 1))
        if key == "port":
            return int(value)
    print(f"Warning: 'port' key not found in {dotenv}, using 12345")
    return 12345


HOST = "127.0.0.1"
PORT = load_port()


def main() -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(b"dummy")
            data = s.recv(1024)
            print(f"Received: {data.decode()}")
    except Exception as e:
        print(f"Failed to get get data: {e}")


if __name__ == "__main__":
    main()
