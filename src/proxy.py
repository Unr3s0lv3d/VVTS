#!/usr/bin/env python3
import sys
import socket
import threading
import select
import time

MAX_LIFETIME = 2 * 60 * 60

def tunnel(src, dst):
    try:
        while True:
            r, _, _ = select.select([src, dst], [], [], 60)
            if not r:
                break
            for s in r:
                try:
                    d = s.recv(4096)
                    if not d:
                        return
                    (dst if s is src else src).sendall(d)
                except:
                    return
    except:
        pass

def handle(conn):
    try:
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return
            buf += chunk

        end = buf.index(b"\r\n\r\n")
        head = buf[:end]
        body = buf[end + 4:]
        lines = head.split(b"\r\n")
        parts = lines[0].decode("utf-8", errors="replace").split(" ", 2)
        if len(parts) != 3:
            return
        method, target, version = parts

        if method.upper() == "CONNECT":
            host, port = target.rsplit(":", 1)
            try:
                remote = socket.create_connection((host, int(port)), timeout=15)
            except:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tunnel(conn, remote)
            remote.close()
        else:
            if target.startswith("http://"):
                rest = target[7:]
                slash = rest.find("/")
                host_port = rest[:slash] if slash != -1 else rest
                path = rest[slash:] if slash != -1 else "/"
                host = host_port.rsplit(":", 1)[0] if ":" in host_port else host_port
                port = int(host_port.rsplit(":", 1)[1]) if ":" in host_port else 80
            else:
                path = target
                host, port = None, 80
                for line in lines[1:]:
                    if line.lower().startswith(b"host:"):
                        val = line[5:].strip().decode()
                        host = val.rsplit(":", 1)[0] if ":" in val else val
                        port = int(val.rsplit(":", 1)[1]) if ":" in val else 80
                        break
                if not host:
                    return

            new_lines = ["{} {} {}".format(method, path, version).encode()]
            for line in lines[1:]:
                if not line.lower().startswith(b"proxy-"):
                    new_lines.append(line)
            request = b"\r\n".join(new_lines) + b"\r\n\r\n" + body

            try:
                remote = socket.create_connection((host, port), timeout=15)
                remote.sendall(request)
                while True:
                    d = remote.recv(4096)
                    if not d:
                        break
                    conn.sendall(d)
                remote.close()
            except:
                pass
    except:
        pass
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: proxy.py <port>\n")
        sys.exit(1)

    port = int(sys.argv[1])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(50)
    srv.settimeout(30)

    sys.stdout.write("started\n")
    sys.stdout.flush()

    start_time = time.monotonic()
    while time.monotonic() - start_time < MAX_LIFETIME:
        try:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        except socket.timeout:
            continue
        except:
            break

    srv.close()

if __name__ == "__main__":
    main()
