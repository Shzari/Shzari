from __future__ import annotations

from typing import Any

from app.compat import legacy_runtime as _legacy

# Explicit legacy symbol bindings
for _name, _value in _legacy.__dict__.items():
    if _name.startswith("__"):
        continue
    globals().setdefault(_name, _value)


def _ldap_connect(
    server_host: str,
    port: int,
    use_ssl: bool,
    start_tls: bool,
    timeout: int,
    user: str | None = None,
    password: str | None = None,
) -> Any:
    tls_config = Tls(validate=ssl.CERT_NONE)
    server = Server(
        server_host,
        port=port,
        use_ssl=use_ssl,
        connect_timeout=timeout,
        get_info=ALL,
        tls=tls_config,
    )
    conn = Connection(
        server,
        user=user,
        password=password,
        auto_bind=False,
        raise_exceptions=True,
        receive_timeout=timeout,
    )
    conn.open()
    if start_tls and not use_ssl:
        conn.start_tls()
    conn.bind()
    return conn


def _ldap_resolve_user_dn(username: str, settings: dict[str, Any]) -> tuple[str, str]:
    template = str(settings.get("user_dn_template", "")).strip()
    if template:
        if "{username}" not in template:
            return "", "LDAP user DN template must include {username}."
        try:
            return template.format(username=username), ""
        except Exception:
            return "", "LDAP user DN template is invalid."

    base_dn = str(settings.get("base_dn", "")).strip()
    if not base_dn:
        return "", "LDAP base DN is required when user DN template is empty."

    raw_filter = str(settings.get("user_search_filter", "(sAMAccountName={username})")).strip()
    search_filter = raw_filter or "(sAMAccountName={username})"
    escaped_username = username
    if escape_filter_chars is not None:
        escaped_username = escape_filter_chars(username)
    try:
        search_filter = search_filter.format(username=escaped_username)
    except Exception:
        return "", "LDAP search filter must include {username} placeholder."

    bind_dn = str(settings.get("bind_dn", "")).strip() or None
    bind_password = str(settings.get("bind_password", "")) if bind_dn else None
    try:
        conn = _ldap_connect(
            str(settings.get("server", "")).strip(),
            int(settings.get("port", 389) or 389),
            bool(settings.get("use_ssl")),
            bool(settings.get("start_tls")),
            int(settings.get("timeout", 5) or 5),
            bind_dn,
            bind_password,
        )
    except Exception as exc:
        return "", f"LDAP bind/search connection failed: {exc}"

    try:
        conn.search(search_base=base_dn, search_filter=search_filter, search_scope=SUBTREE, attributes=["distinguishedName"])
    except LDAPException as exc:
        message = str(exc)
        if "noSuchObject" in message or "NO_SUCH_OBJECT" in message:
            return "", f"LDAP search base was not found: '{base_dn}'. Check Base DN in LDAP settings."
        return "", f"LDAP user search failed: {message}"
    except OSError as exc:
        return "", f"LDAP user search connection failed: {exc}"
    except Exception as exc:
        return "", f"LDAP user search failed: {exc}"
    try:
        if len(conn.entries) == 0:
            return "", "LDAP user not found."
        if len(conn.entries) > 1:
            return "", "LDAP search returned multiple users; refine search filter."
        return str(conn.entries[0].entry_dn), ""
    finally:
        try:
            conn.unbind()
        except Exception:
            pass


def authenticate_with_ldap(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    if not LDAP3_AVAILABLE:
        return False, "LDAP login is unavailable because ldap3 is not installed."

    server_host = str(settings.get("server", "")).strip()
    if not server_host:
        return False, "LDAP server is not configured."

    user_dn, dn_error = _ldap_resolve_user_dn(username, settings)
    if dn_error:
        return False, dn_error
    if not user_dn:
        return False, "Failed to resolve LDAP user DN."

    try:
        conn = _ldap_connect(
            server_host,
            int(settings.get("port", 389) or 389),
            bool(settings.get("use_ssl")),
            bool(settings.get("start_tls")),
            int(settings.get("timeout", 5) or 5),
            user_dn,
            password,
        )
        try:
            conn.unbind()
        except Exception:
            pass
        return True, "Authenticated by LDAP."
    except LDAPException as exc:
        message = str(exc)
        if "invalidCredentials" in message or "INVALID_CREDENTIALS" in message:
            return False, "Incorrect username or password."
        return False, "LDAP authentication failed."
    except OSError as exc:
        return False, f"LDAP connection failed: {exc}"


def _radius_attr(attr_type: int, value: bytes) -> bytes:
    length = len(value) + 2
    return bytes([attr_type, length]) + value


def _radius_encrypt_user_password(password: str, secret: bytes, request_authenticator: bytes) -> bytes:
    pwd_bytes = password.encode("utf-8")
    padding = 16 - (len(pwd_bytes) % 16)
    if padding != 16:
        pwd_bytes += b"\x00" * padding

    encrypted = b""
    last = request_authenticator
    for i in range(0, len(pwd_bytes), 16):
        block = pwd_bytes[i : i + 16]
        digest = hashlib.md5(secret + last).digest()
        cipher = bytes(a ^ b for a, b in zip(block, digest))
        encrypted += cipher
        last = cipher
    return encrypted


def _authenticate_radius_server(
    username: str,
    password: str,
    server: str,
    port: int,
    shared_secret: str,
    timeout: int,
    nas_ip: str,
) -> tuple[bool, str]:
    if not server or not shared_secret:
        return False, "Server/secret missing"

    secret = shared_secret.encode("utf-8")
    identifier = random.randint(0, 255)
    request_authenticator = os.urandom(16)

    attrs = b""
    attrs += _radius_attr(ATTR_USER_NAME, username.encode("utf-8"))
    attrs += _radius_attr(ATTR_USER_PASSWORD, _radius_encrypt_user_password(password, secret, request_authenticator))

    try:
        attrs += _radius_attr(ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip))
    except OSError:
        pass

    attrs += _radius_attr(ATTR_NAS_PORT, struct.pack("!I", 0))
    attrs += _radius_attr(ATTR_SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_LOGIN))

    packet_len = 20 + len(attrs)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, packet_len) + request_authenticator + attrs

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        response, _ = sock.recvfrom(4096)
    except socket.timeout:
        return False, f"Timeout from ISE {server}:{port}"
    except OSError as exc:
        return False, f"Connection error to ISE {server}:{port}: {exc}"
    finally:
        sock.close()

    if len(response) < 20:
        return False, f"Invalid response from ISE {server}:{port}"

    code, recv_identifier, recv_length = struct.unpack("!BBH", response[:4])
    recv_authenticator = response[4:20]
    response_attrs = response[20:recv_length]

    if recv_identifier != identifier:
        return False, f"Identifier mismatch from ISE {server}:{port}"

    expected_auth = hmac.new(secret, response[:4] + request_authenticator + response_attrs, hashlib.md5).digest()
    if expected_auth != recv_authenticator:
        return False, f"Authenticator check failed from ISE {server}:{port}"

    if code == ACCESS_ACCEPT:
        return True, f"Authenticated by ISE {server}:{port}"
    if code == ACCESS_REJECT:
        return False, f"Rejected by ISE {server}:{port}"
    return False, f"Unsupported response code {code} from ISE {server}:{port}"


def authenticate_with_ise(username: str, password: str, settings: dict[str, Any]) -> tuple[bool, str]:
    timeout = int(settings.get("timeout", 5) or 5)
    nas_ip = str(settings.get("nas_ip", "127.0.0.1")).strip()

    primary_server = str(settings.get("primary_server", "")).strip()
    primary_port = int(settings.get("primary_port", 1812) or 1812)
    primary_secret = str(settings.get("primary_shared_secret", ""))

    secondary_server = str(settings.get("secondary_server", "")).strip()
    secondary_port = int(settings.get("secondary_port", 1812) or 1812)
    secondary_secret = str(settings.get("secondary_shared_secret", ""))

    if not primary_server or not primary_secret:
        return False, "Primary ISE server and primary secret are required."

    ok, message = _authenticate_radius_server(username, password, primary_server, primary_port, primary_secret, timeout, nas_ip)
    if ok:
        return True, message

    if secondary_server and secondary_secret:
        ok2, msg2 = _authenticate_radius_server(
            username,
            password,
            secondary_server,
            secondary_port,
            secondary_secret,
            timeout,
            nas_ip,
        )
        if ok2:
            return True, msg2
        return False, f"Primary failed: {message}. Secondary failed: {msg2}."

    return False, message
