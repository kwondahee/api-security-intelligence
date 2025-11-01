import asyncio
import random
import time
from typing import Any, Dict, Iterable, List, Optional

import httpx

def make_auth_header(user_id: Optional[str]) -> Dict[str, str]:
    if not user_id:
        return {}
    return {"Authorization": f"Bearer user:{user_id}"}

class Endpoints:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def health(self):
        return f"{self.base}/health"

    def public_status(self):
        return f"{self.base}/api/v1/public/status"

    def user(self, uid: str):
        return f"{self.base}/rest/user/{uid}"

    def users_admin_only(self):
        return f"{self.base}/rest/users"

    def tenant_res(self, tenant: str, rid: str):
        return f"{self.base}/v2/tenant/{tenant}/resources/{rid}"

    def admin_users(self):
        return f"{self.base}/admin/users"

    def search(self):
        return f"{self.base}/search"

    def echo(self):
        return f"{self.base}/echo"

    def files(self):
        return f"{self.base}/files"

    def api_docs(self):
        return f"{self.base}/api-docs"


SQLI = ["' OR 1=1 --", "' OR '1'='1' --", "\" OR 1=1 --"]
XSS  = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
TRAV = ["../../etc/passwd", "%2e%2e/%2e%2e/etc/passwd", "..%2f..%2fetc%2fpasswd"]

async def flow_public(client: httpx.AsyncClient, ep: Endpoints):
    return [client.get(ep.public_status())]

async def flow_access(client: httpx.AsyncClient, ep: Endpoints, actors: List[str]):
    coros = []
    for target in ["1", "24", "99"]:
        coros.append(client.get(ep.user(target)))
    if actors:
        coros.append(client.get(ep.users_admin_only(), headers=make_auth_header(random.choice(actors))))
    else:
        coros.append(client.get(ep.users_admin_only()))
    return coros

async def flow_tenant(client: httpx.AsyncClient, ep: Endpoints, actors: List[str]):
    hdr = make_auth_header(random.choice(actors) if actors else None)
    return [client.get(ep.tenant_res("T001", "R101"), headers=hdr)]

async def flow_auth(client: httpx.AsyncClient, ep: Endpoints, actors: List[str]):
    coros = []
    coros.append(client.get(ep.admin_users()))
    coros.append(client.get(ep.admin_users(), headers={"Authorization": "Bearer user:1"}))
    coros.append(client.post(ep.admin_users(), headers={"Authorization": "Bearer user:99"}, json={"op": "create", "name": "bob"}))
    return coros

async def flow_input(client: httpx.AsyncClient, ep: Endpoints, enable_sqli=True, enable_xss=True, enable_trav=True):
    coros = []
    if enable_sqli:
        q = random.choice(SQLI)
        coros.append(client.get(ep.search(), params={"q": q}))
    else:
        coros.append(client.get(ep.search(), params={"q": "hello"}))

    if enable_xss:
        x = random.choice(XSS)
        coros.append(client.post(ep.echo(), json={"q": x}))

    if enable_trav:
        t = random.choice(TRAV)
        coros.append(client.get(ep.files(), params={"path": t}))

    return coros

async def flow_docs(client: httpx.AsyncClient, ep: Endpoints):
    return [client.get(ep.api_docs())]

async def pump(
    base_url: str,
    flows: Iterable[str],
    actors: List[str],
    rps: int,
    duration_seconds: int,
    enable_sqli=True,
    enable_xss=True,
    enable_traversal=True,
    log_json=True,
    logger_print=print,
):
    ep = Endpoints(base_url)
    timeout = httpx.Timeout(read=5.0, write=5.0, connect=3.0, pool=3.0)
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=100)
    async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
        start = time.time()
        sent = 0

        async def one_tick():
            nonlocal sent
            coros = []
            want = {
                "public": lambda: flow_public(client, ep),
                "access": lambda: flow_access(client, ep, actors),
                "tenant": lambda: flow_tenant(client, ep, actors),
                "auth":   lambda: flow_auth(client, ep, actors),
                "input":  lambda: flow_input(client, ep, enable_sqli, enable_xss, enable_traversal),
                "docs":   lambda: flow_docs(client, ep),
            }
            selected = set(flows) if "all" not in flows else set(want.keys())
            for key in selected:
                coros += await want[key]()

            if rps > 0 and len(coros) > rps:
                coros = random.sample(coros, rps)

            results = await asyncio.gather(*coros, return_exceptions=True)
            sent += len(coros)

            now = time.time()
            for r in results:
                try:
                    if isinstance(r, httpx.Response):
                        item = {
                            "ts": now,
                            "req": {"method": r.request.method, "url": str(r.request.url)},
                            "res": {"code": r.status_code, "len": int(r.headers.get("Content-Length", 0) or 0)},
                        }
                        logger_print(item if not log_json else __to_json(item))
                except Exception as e:
                    logger_print({"error": str(e)})

        while time.time() - start < duration_seconds:
            tick_start = time.time()
            await one_tick()
            elapsed = time.time() - tick_start
            await asyncio.sleep(max(0.0, 1.0 - elapsed))

        return {"sent": sent, "duration": round(time.time() - start, 2)}

def __to_json(obj: Dict[str, Any]) -> str:
    try:
        import orjson
        return orjson.dumps(obj).decode()
    except Exception:
        import json
        return json.dumps(obj)
