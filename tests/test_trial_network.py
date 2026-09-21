"""Trial isolation; Docker tests opt in with CYBERGYM_DOCKER_TESTS=1."""

import os
import time
from contextlib import ExitStack
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_network
from threading import Thread
from unittest.mock import MagicMock, patch
from uuid import uuid4

import docker
import pytest
from docker.errors import APIError, NotFound

from cybergym.firewall.proxy import (
    PROXY_SYSCTLS,
    TRIAL_POOL_LABEL,
    FirewallProxyManager,
)


@pytest.fixture(autouse=True)
def default_pool(monkeypatch):
    monkeypatch.setenv("CYBERGYM_TRIAL_NETWORK_POOL", "198.18.0.0/15")


@pytest.mark.parametrize("failure", ["reload", "disconnect", "remove"])
@pytest.mark.parametrize("body_error", [False, True])
def test_cleanup_failures_preserve_result_and_attempt_removal(
    failure, body_error, caplog
):
    net = MagicMock(name="trial-network")
    net.name = "trial-test"
    net.attrs = {"Containers": {"first": {}, "second": {}}}
    getattr(net, failure).side_effect = APIError("injected Docker failure")

    def run():
        try:
            if body_error:
                raise ValueError("original trial failure")
            return "evaluation result"
        finally:
            FirewallProxyManager._cleanup_trial_network(net)

    if body_error:
        with pytest.raises(ValueError, match="original trial failure"):
            run()
    else:
        assert run() == "evaluation result"
    net.remove.assert_called_once()
    if failure != "reload":
        assert net.disconnect.call_count == 2
    assert "trial-test" in caplog.text and "injected Docker failure" in caplog.text


def test_cleanup_tolerates_removed_network_and_endpoints():
    net = MagicMock()
    net.reload.side_effect = NotFound("already removed")
    FirewallProxyManager._cleanup_trial_network(net)
    net.remove.assert_not_called()
    net.reload.side_effect = None
    net.attrs = {"Containers": {"gone": {}, "remaining": {}}}
    net.disconnect.side_effect = [NotFound("already removed"), None]
    net.remove.side_effect = NotFound("already removed")
    FirewallProxyManager._cleanup_trial_network(net)
    assert net.disconnect.call_count == 2
    net.remove.assert_called_once()


@pytest.mark.parametrize("pool", [None, "192.0.2.0/24"])
@patch("cybergym.firewall.proxy.docker.from_env")
def test_rejects_missing_or_mismatched_deny_policy(mock_docker, pool):
    client = mock_docker.return_value
    client.containers.get.return_value.attrs = {
        "HostConfig": {"Sysctls": PROXY_SYSCTLS},
        "Config": {"Labels": {TRIAL_POOL_LABEL: pool}},
    }
    with pytest.raises(RuntimeError, match="deny policy"):
        with FirewallProxyManager().trial_network():
            pytest.fail("Unsafe proxy accepted")
    client.networks.create.assert_not_called()


@patch("cybergym.firewall.proxy.docker.from_env")
def test_custom_pool_denied_before_any_allow(mock_docker, monkeypatch):
    monkeypatch.setenv("CYBERGYM_TRIAL_NETWORK_POOL", "192.0.2.0/24")
    mgr = FirewallProxyManager(extra_ips=["0.0.0.0/0"])
    conf = mgr._generate_squid_conf()
    assert "acl trial_networks dst 192.0.2.0/24" in conf
    assert conf.index("http_access deny trial_networks") < conf.index(
        "http_access allow"
    )
    mgr._create_trial_network()
    kwargs = mock_docker.return_value.networks.create.call_args.kwargs
    subnet = ip_network(kwargs["ipam"]["Config"][0]["Subnet"])
    assert subnet.subnet_of(mgr.trial_pool) and subnet.prefixlen == 29
    assert kwargs["enable_ipv6"] is False


@patch("cybergym.firewall.proxy.docker.from_env")
def test_subnet_collision_retry_is_bounded(mock_docker):
    create = mock_docker.return_value.networks.create
    collision = APIError("Pool overlaps with other one on this address space")
    create.side_effect = [collision, MagicMock()]
    FirewallProxyManager()._create_trial_network()
    assert create.call_count == 2
    create.reset_mock()
    create.side_effect = collision
    with pytest.raises(APIError, match="Pool overlaps"):
        FirewallProxyManager()._create_trial_network()
    assert create.call_count == 16
    create.reset_mock()
    create.side_effect = APIError("permission denied")
    with pytest.raises(APIError, match="permission denied"):
        FirewallProxyManager()._create_trial_network()
    create.assert_called_once()


@pytest.mark.parametrize("failure", [None, "connect", "body"])
@patch("cybergym.firewall.proxy.docker.from_env")
def test_trial_network_cleanup(mock_docker, failure):
    client = mock_docker.return_value
    client.containers.get.return_value.attrs = {
        "HostConfig": {"Sysctls": PROXY_SYSCTLS},
        "Config": {"Labels": {TRIAL_POOL_LABEL: "198.18.0.0/15"}},
    }
    original = MagicMock()
    original.attrs = {"IPAM": {"Config": [{"Gateway": "172.18.0.1"}]}}
    net = client.networks.create.return_value
    net.name = "trial"
    net.attrs = {
        "IPAM": {"Config": [{"Gateway": "172.19.0.1"}]},
        "Containers": {"endpoint": {}},
    }
    net.containers = [MagicMock()]
    client.networks.get.side_effect = lambda name: net if name == "trial" else original
    mgr = FirewallProxyManager(no_proxy=["localhost", "172.18.0.1"])
    original_name = mgr.network_name
    if failure == "connect":
        net.connect.side_effect = RuntimeError("connect")

    def run():
        with mgr.trial_network() as name:
            assert name == mgr.network_name == "trial"
            assert mgr.no_proxy == ["localhost", "172.19.0.1"]
            if failure == "body":
                raise RuntimeError("body")

    if failure:
        with pytest.raises(RuntimeError, match=failure):
            run()
    else:
        run()
    assert mgr.network_name == original_name
    assert mgr.no_proxy == ["localhost", "172.18.0.1"]
    net.disconnect.assert_called_once_with("endpoint", force=True)
    net.remove.assert_called_once()


@pytest.mark.parametrize("sysctls", [{}, {"net.ipv4.ip_forward": "0"}])
@patch("cybergym.firewall.proxy.docker.from_env")
def test_rejects_legacy_proxy(mock_docker, sysctls):
    client = mock_docker.return_value
    client.containers.get.return_value.attrs = {"HostConfig": {"Sysctls": sysctls}}
    with pytest.raises(RuntimeError, match="disable IP forwarding"):
        with FirewallProxyManager().trial_network():
            pytest.fail("Unsafe proxy accepted")
    client.networks.create.assert_not_called()


@pytest.mark.skipif(os.getenv("CYBERGYM_DOCKER_TESTS") != "1", reason="Docker opt-in")
@pytest.mark.parametrize("broad_run_allowlist", [False, True])
def test_docker_trial_isolation(broad_run_allowlist, tmp_path):
    """Real Squid, two trials, host submission endpoint, and no external services."""
    client = docker.from_env()
    prefix = f"eg-isolation-test-{uuid4().hex[:8]}"
    private_names = []
    with ExitStack() as resources:

        def container(network=None):
            c = client.containers.run(
                "python:3.12-slim", ["sleep", "300"], detach=True, network=network
            )
            resources.callback(c.remove, force=True)
            return c

        def ip(c, network):
            c.reload()
            return c.attrs["NetworkSettings"]["Networks"][network]["IPAddress"]

        def serve(c, marker):
            FirewallProxyManager._put_file(c, "/tmp/marker", marker)
            c.exec_run(
                ["python", "-m", "http.server", "18080", "--directory", "/tmp"],
                detach=True,
            )
            for _ in range(50):
                if fetch(c, "127.0.0.1")[0] == "200":
                    return
                time.sleep(0.1)
            pytest.fail("HTTP test server did not start")

        def fetch(c, host, proxy=None, port=18080, environment=None):
            proxies = {"http": proxy} if proxy else {}
            code = (
                "import urllib.request, urllib.error\n"
                f"op=urllib.request.build_opener(urllib.request.ProxyHandler({proxies!r}))\n"
                "try:\n"
                f" r=op.open('http://{host}:{port}/marker', timeout=3)\n"
                " print(r.status, r.read().decode())\n"
                "except urllib.error.HTTPError as e: print(e.code)\n"
                "except OSError: print('blocked')\n"
            )
            result = c.exec_run(["python", "-c", code], environment=environment)
            assert result.exit_code == 0, result.output
            return result.output.decode().strip().split(maxsplit=1)

        def connect_status(c, target, mgr):
            request = f"CONNECT {target}:18080 HTTP/1.1\r\nHost: {target}:18080\r\n\r\n"
            result = c.exec_run(
                [
                    "python",
                    "-c",
                    (
                        "import socket; "
                        f"s=socket.create_connection(('{mgr.container_name}',3128),timeout=3); "
                        f"s.sendall({request.encode()!r}); "
                        "print(s.recv(4096).split()[1].decode())"
                    ),
                ]
            )
            assert result.exit_code == 0, result.output
            return result.output.decode().strip()

        origin = container()
        serve(origin, "allowed")
        origin_ip = ip(origin, "bridge")
        managers = []
        for suffix in ("a", "b"):
            mgr = FirewallProxyManager(
                container_name=f"{prefix}-proxy", network_name=prefix,
                extra_ips=["0.0.0.0/0"] if broad_run_allowlist else [origin_ip],
            )
            if suffix == "a":
                resources.callback(mgr.stop_all)
                mgr.start()
            else:
                mgr.connect()
            managers.append(mgr)
        run_a, run_b = managers
        # Old launchers cannot silently keep exchanging data on infrastructure.
        legacy_a, legacy_b = container(prefix), container(prefix)
        serve(legacy_a, "legacy")
        assert fetch(legacy_b, ip(legacy_a, prefix)) == ["blocked"]
        # Preserve access to a controller bound to the infrastructure gateway.
        gateway = run_a.host_gateway
        (tmp_path / "marker").write_text("host-controller")
        host_server = ThreadingHTTPServer(
            (gateway, 0), partial(SimpleHTTPRequestHandler, directory=str(tmp_path))
        )
        resources.callback(host_server.server_close)
        resources.callback(host_server.shutdown)
        Thread(target=host_server.serve_forever, daemon=True).start()
        with ExitStack() as trials:
            for mgr in managers:
                private_names.append(trials.enter_context(mgr.trial_network()))
            a, b = container(run_a.network_name), container(run_a.network_name)
            a_ip = ip(a, run_a.network_name)
            marker = uuid4().hex
            serve(a, marker)
            assert fetch(a, a_ip)[0] == "200"  # Listener is reachable locally.
            # Reproduce the old shared-bridge defect, then isolate this trial.
            assert fetch(b, a_ip) == ["200", marker]
            client.networks.get(run_a.network_name).disconnect(b)
            client.networks.get(run_b.network_name).connect(b)
            serve(b, uuid4().hex)
            a_ip = ip(a, run_a.network_name)
            b_ip = ip(b, run_b.network_name)
            assert fetch(b, b_ip)[0] == "200"
            assert fetch(b, a_ip) == ["blocked"]
            assert fetch(a, b_ip) == ["blocked"]
            assert fetch(a, origin_ip) == ["blocked"]
            assert fetch(a, origin_ip, run_a.proxy_url) == ["200", "allowed"]
            assert fetch(b, origin_ip, run_b.proxy_url) == ["200", "allowed"]
            assert fetch(b, a_ip, run_b.proxy_url) == ["403"]
            assert connect_status(b, a_ip, run_b) == "403"
            assert fetch(a, b_ip, run_a.proxy_url) == ["403"]
            assert connect_status(a, b_ip, run_a) == "403"
            assert fetch(
                b,
                gateway,
                run_b.proxy_url,
                host_server.server_port,
                environment=run_b.env_vars(),
            ) == ["200", "host-controller"]
            for target in [a.name, f"[::ffff:{a_ip}]"]:
                assert fetch(b, target, run_b.proxy_url) == ["403"]
                assert connect_status(b, target, run_b) == "403"
            assert connect_status(b, origin_ip, run_b) == "200"
            proxy = client.containers.get(run_a.container_name)
            result = proxy.exec_run([
                "cat", "/proc/sys/net/ipv4/ip_forward",
                "/proc/sys/net/ipv6/conf/all/forwarding",
            ])
            assert result.exit_code == 0 and result.output == b"0\n0\n"

        # Context exit disconnects even retained containers and removes networks.
        for name in private_names:
            with pytest.raises(docker.errors.NotFound):
                client.networks.get(name)


@patch("cybergym.firewall.proxy.docker.from_env")
def test_rejects_legacy_shared_bridge(mock_docker):
    mock_docker.return_value.networks.get.return_value.attrs = {
        "Internal": True, "Options": {}}
    with pytest.raises(RuntimeError, match="Legacy shared agent network"):
        FirewallProxyManager().start()
