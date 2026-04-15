"""
Domain-allowlist proxy for agent containers.

Runs a Squid forward proxy that bridges between an **internal** Docker network
(no internet route) and the default bridge (internet).  Agent containers sit
on the internal network and can *only* reach the proxy — even if a program
ignores HTTP_PROXY, direct connections fail because there is no route out.

Architecture
------------
    Agent ──(cybergym-internal, no internet)──▶ Squid ──(bridge)──▶ Internet
                                                       filtered by domain

Usage
-----
    from cybergym.firewall import FirewallProxyManager, load_allowlist

    proxy = FirewallProxyManager(
        allowed_domains=load_allowlist("allowlist.txt"),
    )
    proxy.start()

    # The host is reachable at proxy.host_gateway (internal bridge gateway).
    # This IP is auto-added to NO_PROXY so containers bypass the proxy for it.
    server_url = f"http://{proxy.host_gateway}:13338"

    # Create agent container on the internal network:
    container = client.containers.run(
        image=..., detach=True,
        network=proxy.network_name,
    )

    # Merge proxy env vars into docker exec:
    envs.update(proxy.env_vars())

    # Cleanup (optional — proxy is shared across runs):
    proxy.stop()
"""

import argparse
import io
import json
import logging
import tarfile
import time
from pathlib import Path

from docker.errors import APIError, NotFound

import docker

logger = logging.getLogger(__name__)

PROXY_CONTAINER_NAME = "cybergym-proxy"
PROXY_IMAGE = "ubuntu/squid:latest"
PROXY_PORT = 3128
INTERNAL_NETWORK = "cybergym-internal"

DEFAULT_ALLOWLIST_PATH = Path(__file__).with_name("default_allowlist.txt")

DOMAIN_ALLOWLIST_CONTAINER_PATH = "/etc/squid/allowed_domains.txt"
IP_ALLOWLIST_CONTAINER_PATH = "/etc/squid/allowed_ips.txt"

SQUID_CONF_TEMPLATE = """\
# --- CyberGym domain-allowlist proxy ---

acl SSL_ports port 443 {extra_ports}
acl Safe_ports port 80 443 {extra_ports}
acl CONNECT method CONNECT

# Allowed destinations — loaded from external files
acl allowed_domains dstdomain "{domain_allowlist_path}"
{ip_acl}

# Rules
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow CONNECT allowed_domains
{ip_connect_rule}
http_access allow allowed_domains
{ip_rule}
http_access deny all

http_port {port}

# Disable disk cache
cache deny all

# Logging (Squid runs as user 'proxy' which cannot write to /dev/stdout)
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
"""


def load_allowlist(path: str | Path) -> list[str]:
    """Load domain allowlist from a text file.

    The file should contain one domain per line in Squid ``dstdomain``
    format — a leading dot means "match this domain and all subdomains"
    (e.g. ``.pypi.org``).  Empty lines and lines starting with ``#``
    are ignored.

    Returns:
        List of domain strings, preserved exactly as written in the file.
    """
    domains: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


class FirewallProxyManager:
    """Manages a Squid proxy container with network-level enforcement."""

    def __init__(
        self,
        allowlist_path: str | Path | None = None,
        extra_domains: list[str] | None = None,
        ip_allowlist_path: str | Path | None = None,
        extra_ips: list[str] | None = None,
        no_proxy: list[str] | None = None,
        proxy_image: str = PROXY_IMAGE,
        proxy_port: int = PROXY_PORT,
        container_name: str = PROXY_CONTAINER_NAME,
        network_name: str = INTERNAL_NETWORK,
    ):
        self.allowlist_path = Path(allowlist_path or DEFAULT_ALLOWLIST_PATH).resolve()
        if not self.allowlist_path.is_file():
            raise FileNotFoundError(f"Allowlist file not found: {self.allowlist_path}")
        self.extra_domains = extra_domains or []
        self.ip_allowlist_path = (
            Path(ip_allowlist_path).resolve() if ip_allowlist_path else None
        )
        if self.ip_allowlist_path and not self.ip_allowlist_path.is_file():
            raise FileNotFoundError(
                f"IP allowlist file not found: {self.ip_allowlist_path}"
            )
        self.extra_ips = extra_ips or []
        self.no_proxy = no_proxy or []
        self.proxy_image = proxy_image
        self.proxy_port = proxy_port
        self.container_name = container_name
        self.network_name = network_name
        self._client = docker.from_env()

    # -- public API ----------------------------------------------------------

    @property
    def proxy_url(self) -> str:
        return f"http://{self.container_name}:{self.proxy_port}"

    def env_vars(self) -> dict[str, str]:
        """Return env-var dict suitable for ``docker exec -e``."""
        return {
            "HTTP_PROXY": self.proxy_url,
            "HTTPS_PROXY": self.proxy_url,
            "NO_PROXY": ",".join(self.no_proxy),
            "http_proxy": self.proxy_url,
            "https_proxy": self.proxy_url,
            "no_proxy": ",".join(self.no_proxy),
        }

    @property
    def host_gateway(self) -> str:
        """Return the host gateway IP on the internal network.

        Containers on the internal network can reach the host at this IP
        without going through the proxy.  Available after ``start()``.
        """
        net = self._client.networks.get(self.network_name)
        configs = net.attrs.get("IPAM", {}).get("Config", [])
        if configs and configs[0].get("Gateway"):
            return configs[0]["Gateway"]
        raise RuntimeError(f"No gateway found for network {self.network_name}")

    def connect(self) -> None:
        """Connect to an already-running proxy without starting anything.

        Populates ``no_proxy`` with the host gateway and localhost so that
        ``env_vars()`` returns usable values.  Raises if the network or
        proxy container does not exist.
        """
        # Verify infrastructure is up
        self._client.networks.get(self.network_name)
        c = self._client.containers.get(self.container_name)
        if c.status != "running":
            raise RuntimeError(
                f"Proxy container {self.container_name} exists but is not running "
                f"(status: {c.status})"
            )

        gw = self.host_gateway
        if gw not in self.no_proxy:
            self.no_proxy.append(gw)
        for local in ["localhost", "127.0.0.1"]:
            if local not in self.no_proxy:
                self.no_proxy.append(local)

        logger.info(
            "Connected to existing proxy: url=%s network=%s",
            self.proxy_url,
            self.network_name,
        )

    def start(self) -> None:
        """Ensure the internal network and proxy container are running."""
        self._ensure_network()
        # Auto-add host gateway so containers can reach the host directly
        gw = self.host_gateway
        if gw not in self.no_proxy:
            self.no_proxy.append(gw)
        if gw not in self.extra_ips:
            self.extra_ips.append(gw)

        for local in ["localhost", "127.0.0.1"]:
            if local not in self.no_proxy:
                self.no_proxy.append(local)

        self._ensure_proxy()

    def update(self) -> None:
        """Restart the proxy container with the current configuration.

        Useful after modifying the allowlist files on the host. The new
        container gets fresh copies of all config files.
        The internal network is preserved so other containers stay connected.
        """
        self.stop()
        self._ensure_network()
        gw = self.host_gateway
        if gw not in self.extra_ips:
            self.extra_ips.append(gw)
        self._ensure_proxy()

    def stop(self) -> None:
        """Stop and remove the proxy container (network is left for reuse)."""
        try:
            c = self._client.containers.get(self.container_name)
            c.remove(force=True)
            logger.info("Removed proxy container %s", self.container_name)
        except NotFound:
            pass

    def stop_all(self) -> None:
        """Stop proxy and remove the internal network (disconnects lingering containers)."""
        self.stop()
        try:
            net = self._client.networks.get(self.network_name)
            net.reload()
            for c in net.containers:
                logger.info("Disconnecting %s from %s", c.name, self.network_name)
                net.disconnect(c, force=True)
            net.remove()
            logger.info("Removed network %s", self.network_name)
        except NotFound:
            pass

    def status(self) -> dict:
        """Return a dict describing the current infrastructure state."""
        info: dict = {"network": None, "proxy": None}

        try:
            net = self._client.networks.get(self.network_name)
            net.reload()
            info["network"] = {
                "name": self.network_name,
                "internal": net.attrs.get("Internal", False),
                "containers": [c.name for c in net.containers],
            }
        except NotFound:
            pass

        try:
            c = self._client.containers.get(self.container_name)
            c.reload()
            health = c.attrs.get("State", {}).get("Health", {}).get("Status", "unknown")
            info["proxy"] = {
                "name": self.container_name,
                "status": c.status,
                "health": health,
            }
        except NotFound:
            pass

        return info

    # -- internals -----------------------------------------------------------

    def _ensure_network(self) -> None:
        try:
            net = self._client.networks.get(self.network_name)
            if not net.attrs.get("Internal", False):
                raise RuntimeError(
                    f"Network {self.network_name!r} exists but is not internal. "
                    "An external network cannot enforce egress isolation. "
                    "Remove it and let the proxy recreate it, or use a different name."
                )
        except NotFound:
            # internal=True  →  no default route to the internet
            self._client.networks.create(
                self.network_name, driver="bridge", internal=True
            )
            logger.info("Created internal network %s", self.network_name)

    def _ensure_proxy(self) -> None:
        # Already running?
        try:
            c = self._client.containers.get(self.container_name)
            if c.status == "running":
                logger.info("Proxy container already running")
                return
            c.remove(force=True)
        except NotFound:
            pass

        # Create container (stopped), copy config files in, then start.
        # This avoids bind-mounts so the container is self-contained.
        try:
            proxy = self._client.containers.create(
                image=self.proxy_image,
                name=self.container_name,
            )

            # Build merged allowlist contents (file + extra entries)
            domain_content = self._build_allowlist(
                self.allowlist_path, self.extra_domains
            )
            ip_content = self._build_allowlist(self.ip_allowlist_path, self.extra_ips)

            # Copy config files into the container
            self._put_file(proxy, "/etc/squid/squid.conf", self._generate_squid_conf())
            self._put_file(proxy, DOMAIN_ALLOWLIST_CONTAINER_PATH, domain_content)
            if ip_content:
                self._put_file(proxy, IP_ALLOWLIST_CONTAINER_PATH, ip_content)

            proxy.start()

            # Connect proxy to the internal network so agents can reach it
            net = self._client.networks.get(self.network_name)
            net.connect(proxy)
            self._wait_ready(proxy)
            logger.info("Started proxy container %s", self.container_name)
        except APIError as e:
            if "Conflict" in str(e):
                logger.info("Proxy container created by another thread")
            else:
                raise

    @staticmethod
    def _put_file(container, path: str, content: str) -> None:
        """Write *content* into *path* inside a (possibly stopped) container."""
        data = content.encode()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=path.rsplit("/", 1)[-1])
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        container.put_archive(str(Path(path).parent), buf)

    def _wait_ready(self, proxy, timeout: int = 30) -> None:
        """Block until Squid is accepting connections."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            container = self._client.containers.get(proxy.id)
            ret = container.exec_run(
                ["bash", "-c", f"echo > /dev/tcp/127.0.0.1/{self.proxy_port}"]
            )
            if ret.exit_code == 0:
                return
            time.sleep(0.5)
        raise TimeoutError(f"Squid not ready after {timeout}s")

    @staticmethod
    def _build_allowlist(file_path: Path | None, extra_entries: list[str]) -> str:
        """Merge a file and extra entries into a single allowlist string."""
        lines: list[str] = []
        if file_path:
            lines.append(file_path.read_text().rstrip("\n"))
        if extra_entries:
            lines.extend(extra_entries)
        return "\n".join(lines) + "\n" if lines else ""

    def _has_ips(self) -> bool:
        return bool(self.ip_allowlist_path or self.extra_ips)

    def _generate_squid_conf(self) -> str:
        ip_acl = ""
        ip_rule = ""
        ip_connect_rule = ""
        if self._has_ips():
            ip_acl = f'acl allowed_ips dst "{IP_ALLOWLIST_CONTAINER_PATH}"'
            ip_rule = "http_access allow allowed_ips"
            ip_connect_rule = "http_access allow CONNECT allowed_ips"

        # Allow any port for IP-based destinations
        extra_ports = "1-65535" if self._has_ips() else ""

        return SQUID_CONF_TEMPLATE.format(
            domain_allowlist_path=DOMAIN_ALLOWLIST_CONTAINER_PATH,
            ip_acl=ip_acl,
            ip_rule=ip_rule,
            ip_connect_rule=ip_connect_rule,
            extra_ports=extra_ports,
            port=self.proxy_port,
        )


# ======================================================================
# CLI
# ======================================================================


def main():
    parser = argparse.ArgumentParser(
        description="Manage the CyberGym proxy infrastructure.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    # Shared arguments for start/update
    for p in [
        sub.add_parser("start", help="Create network and start proxy"),
        sub.add_parser(
            "update", help="Restart proxy with current config (network preserved)"
        ),
    ]:
        p.add_argument(
            "--allowlist",
            type=Path,
            help="Domain allowlist file (default: built-in list)",
        )
        p.add_argument("--domain", action="append", help="Extra allowed domain")
        p.add_argument("--ip-allowlist", type=Path, help="IP allowlist file")
        p.add_argument("--ip", action="append", help="Extra allowed IP/CIDR")

    sub.add_parser("stop", help="Stop proxy container")
    sub.add_parser("stop-all", help="Stop proxy and remove network")
    sub.add_parser("status", help="Show infrastructure state")

    args = parser.parse_args()
    logging.basicConfig(format="%(asctime)s [%(name)s] %(message)s", level=logging.INFO)

    kwargs: dict = {}
    if args.action in ("start", "update"):
        if getattr(args, "allowlist", None):
            kwargs["allowlist_path"] = args.allowlist
        if getattr(args, "domain", None):
            kwargs["extra_domains"] = args.domain
        if getattr(args, "ip_allowlist", None):
            kwargs["ip_allowlist_path"] = args.ip_allowlist
        if getattr(args, "ip", None):
            kwargs["extra_ips"] = args.ip

    mgr = FirewallProxyManager(**kwargs)

    match args.action:
        case "start":
            mgr.start()
            logger.info(
                "Proxy ready  url=%s  network=%s  host_gateway=%s",
                mgr.proxy_url,
                mgr.network_name,
                mgr.host_gateway,
            )
        case "update":
            mgr.update()
            logger.info(
                "Proxy updated  url=%s  allowlist=%s",
                mgr.proxy_url,
                mgr.allowlist_path,
            )
        case "stop":
            mgr.stop()
        case "stop-all":
            mgr.stop_all()
        case "status":
            print(json.dumps(mgr.status(), indent=2))


if __name__ == "__main__":
    main()
