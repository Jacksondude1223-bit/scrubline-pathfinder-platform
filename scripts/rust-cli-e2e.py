"""Exercise every Rust scrubctl command against the native Rust API."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
base = f"http://127.0.0.1:{port}"
env = dict(
    os.environ,
    SCRUBLINE_API_TOKEN="rust-migration-e2e-operator",
    SCRUBLINE_ENROLL_TOKEN="rust-migration-e2e-enroll",
)
reference_api = ROOT / os.environ.get(
    "PATHFINDER_REFERENCE_API", "target/release/scrub-api"
)


def ctl(*args):
    result = subprocess.run(
        [str(ROOT / "target/release/scrubctl"), "-api", base, *args],
        env=env,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (args, result.stderr)
    return result.stdout


def post(path, data):
    request = urllib.request.Request(
        base + path,
        data=json.dumps(data).encode(),
        headers={
            "Authorization": "Bearer " + env["SCRUBLINE_API_TOKEN"],
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


with tempfile.TemporaryFile() as log:
    api = subprocess.Popen(
        [str(reference_api), "-addr", f"127.0.0.1:{port}"],
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=log,
    )
    try:
        for _ in range(100):
            if api.poll() is not None:
                raise RuntimeError("reference API exited during startup")
            try:
                with urllib.request.urlopen(base + "/health", timeout=1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("reference API did not start")

        node = post(
            "/v1/nodes/register",
            {
                "name": "rust-e2e",
                "region": "us",
                "capacity_gbps": 100,
                "tunnel_src": "192.0.2.1",
            },
        )
        assert json.loads(ctl("nodes"))[0]["id"] == node["node"]["id"]
        ctl("apply", "configs/policy.demo.json")
        ctl("policies")
        ctl("deploy", "managed-protection")
        ctl("fabric")
        assert "PREFIX" in ctl("bgp")
        ctl("ml-load", "configs/ml.samples.json")
        ctl("ml-train")
        assert json.loads(ctl("ml-model"))["ready"]
        ctl("analytics", "1h")
        ctl("attacks", "1h")
        ctl("tenants")

        with tempfile.TemporaryDirectory() as temp:
            tenant = pathlib.Path(temp) / "tenant.json"
            tenant.write_text(json.dumps({
                "id": "rust-customer",
                "name": "Rust customer",
                "prefixes": ["203.0.113.0/24"],
            }))
            assert json.loads(ctl("tenant-add", str(tenant)))["id"] == "rust-customer"
            ctl("tenant-token", "rust-customer")
            ctl("tenant-rm", "rust-customer")
            flow = pathlib.Path(temp) / "flow.json"
            flow.write_text(json.dumps({
                "src_ip": "192.0.2.3",
                "dst_ip": "203.0.113.4",
                "proto": "tcp",
                "sport": 12345,
                "dport": 443,
                "flags": "ack",
                "pps": 20,
            }))
            decision = json.loads(ctl("decide", node["node"]["id"], str(flow)))
            assert "action" in decision, decision
        print("All 16 Rust scrubctl commands succeeded against the Rust API")
    finally:
        api.terminate()
        api.wait(timeout=10)
