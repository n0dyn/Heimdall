"""Action1 API 3.0 client.

Paths and regions match Action1's docs and the current PSAction1 UriMap.
Token requests use form-urlencoded bodies. The client paces itself under the
published 30 requests per minute limit and retries 429 and a single 401.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


REGIONS = {
    "NorthAmerica": "https://app.action1.com/api/3.0",
    "NorthAmerica-2": "https://app.na-2.action1.com/api/3.0",
    "Europe": "https://app.eu.action1.com/api/3.0",
    "Australia": "https://app.au.action1.com/api/3.0",
    "UnitedKingdom": "https://app.uk.action1.com/api/3.0",
}

REGION_LABELS = {
    "NorthAmerica": "North America",
    "NorthAmerica-2": "North America 2",
    "Europe": "Europe",
    "Australia": "Australia",
    "UnitedKingdom": "United Kingdom",
}


class Action1Error(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


class Action1Budget(Action1Error):
    def __init__(self):
        super().__init__(429, "Stopped early to stay under the Action1 request limit")


def base_url_for(region: str) -> str:
    """Region host, unless SIEM_ACTION1_BASE_URL points at a private stand-in."""
    override = (os.getenv("SIEM_ACTION1_BASE_URL") or "").strip()
    if override:
        return override.rstrip("/")
    url = REGIONS.get(region or "")
    if not url:
        raise Action1Error(400, "Unknown Action1 region")
    return url


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _query_int(url: str, key: str):
    query = urllib.parse.urlsplit(url).query
    values = urllib.parse.parse_qs(query).get(key) or []
    if not values:
        return None
    return _as_int(values[-1])


def _page_identity(item) -> str:
    if not isinstance(item, dict):
        return ""
    for key in ("cve_id", "id", "name"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _min_interval() -> float:
    raw = (os.getenv("SIEM_ACTION1_MIN_INTERVAL") or "").strip()
    if not raw:
        return 2.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 2.0


class Action1Client:
    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 min_interval: float = None, max_requests: int = 24, timeout: float = 25):
        self.base_url = (base_url or "").rstrip("/")
        self.client_id = client_id or ""
        self.client_secret = client_secret or ""
        self.min_interval = _min_interval() if min_interval is None else min_interval
        self.max_requests = max_requests
        self.timeout = timeout
        self._access = None
        self._expires_at = 0.0
        self._last = 0.0
        self._calls = 0
        self.budget_hit = False

    def absolute(self, url: str) -> str:
        """Join an API path, or a host-absolute next_page, onto the region base."""
        if url.startswith("http://") or url.startswith("https://"):
            return url
        parsed = urllib.parse.urlsplit(self.base_url)
        base_path = parsed.path.rstrip("/")
        if url.startswith("/") and base_path and (url == base_path or url.startswith(base_path + "/")):
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        return urllib.parse.urljoin(self.base_url.rstrip("/") + "/", url.lstrip("/"))

    def _pace(self):
        if self.min_interval <= 0:
            return
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def _request(self, method: str, path: str, form: dict = None, payload: dict = None,
                 auth: bool = True, _retried_auth: bool = False, _retried_429: int = 0):
        if form is not None and payload is not None:
            raise Action1Error(400, "Action1 request cannot send both a form and a JSON body")
        if self._calls >= self.max_requests:
            raise Action1Budget()
        self._pace()
        self._calls += 1
        url = path if path.startswith("http://") or path.startswith("https://") else self.absolute(path)
        headers = {}
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = "Bearer " + self._token()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw.decode())
        except urllib.error.HTTPError as exc:
            self._drain(exc)
            safe_path = urllib.parse.urlsplit(url).path
            if exc.code == 401 and auth and not _retried_auth:
                self._access = None
                self._expires_at = 0.0
                return self._request(
                    method, path, form=form, payload=payload, auth=True, _retried_auth=True,
                )
            if exc.code == 429 and _retried_429 < 3:
                delay = self._retry_delay(exc, _retried_429)
                if delay > 0:
                    time.sleep(delay)
                return self._request(
                    method, path, form=form, payload=payload, auth=auth,
                    _retried_auth=_retried_auth, _retried_429=_retried_429 + 1,
                )
            raise Action1Error(exc.code, f"Action1 returned {exc.code} for {method} {safe_path}")
        except urllib.error.URLError:
            raise Action1Error(0, "Action1 could not be reached")
        except Action1Error:
            raise
        except Exception:
            raise Action1Error(0, "Action1 could not be reached")

    def _drain(self, exc):
        try:
            exc.read()
        except Exception:
            pass
        try:
            exc.close()
        except Exception:
            pass

    def _retry_delay(self, exc, attempt: int) -> float:
        header = ""
        if exc.headers:
            header = exc.headers.get("Retry-After") or ""
        try:
            return min(60.0, float(header))
        except (TypeError, ValueError):
            return min(60.0, 8.0 * (2 ** attempt))

    def _token(self) -> str:
        if self._access and time.monotonic() < self._expires_at:
            return self._access
        payload = self._request(
            "POST",
            "/oauth2/token",
            form={"client_id": self.client_id, "client_secret": self.client_secret},
            auth=False,
        )
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not token:
            raise Action1Error(401, "Action1 did not return an access token")
        try:
            expires = int(payload.get("expires_in") or 3600)
        except (TypeError, ValueError):
            expires = 3600
        self._access = token
        self._expires_at = time.monotonic() + max(30, expires - 120)
        return token

    def _page_url(self, path: str, limit: int, fields: bool, offset: int = None) -> str:
        base, _, query = path.partition("?")
        parsed = urllib.parse.parse_qs(query, keep_blank_values=True)
        flat = {key: values[-1] for key, values in parsed.items()}
        flat["limit"] = str(int(limit))
        if fields:
            flat["fields"] = "*"
        else:
            flat.pop("fields", None)
        if offset:
            flat["from"] = str(int(offset))
        else:
            flat.pop("from", None)
        return base + "?" + urllib.parse.urlencode(flat)

    def list_collection(self, path: str, max_pages: int = 3, max_items: int = 150,
                        limit: int = 50, fields: bool = True, start: int = 0):
        """Follow next_page, or a from/limit offset when the page omits next_page.

        Vulnerabilities return total_items and from, and do not return next_page.
        Returns (items, complete, total_items). total_items is None when the
        page does not say how large the collection is. budget_hit is set when
        the request cap stops the walk after the items already fetched.
        """
        self.budget_hit = False
        items = []
        total = None
        seen = set()
        pages = 0
        origin = int(start or 0)
        url = self._page_url(path, limit, fields, origin or None)
        last_identity = None
        while url and pages < max_pages and len(items) < max_items:
            if url in seen:
                break
            seen.add(url)
            try:
                page = self._request("GET", url)
            except Action1Budget:
                self.budget_hit = True
                return items[:max_items], False, total
            pages += 1
            if not isinstance(page, dict):
                return items[:max_items], False, total
            batch = page.get("items")
            if not isinstance(batch, list):
                batch = []
            asked = _query_int(url, "from")
            reported = _as_int(page.get("from")) if "from" in page else None
            if asked is not None and reported is not None and reported != asked:
                break
            identity = _page_identity(batch[0]) if batch else ""
            if identity and identity == last_identity:
                break
            if identity:
                last_identity = identity
            items.extend(batch)
            parsed_total = _as_int(page.get("total_items")) if page.get("total_items") not in (None, "") else None
            if parsed_total is not None:
                total = parsed_total
            if total is not None and origin + len(items) >= total:
                return items[:max_items], True, total
            nxt = page.get("next_page") or ""
            if nxt:
                url = self.absolute(str(nxt))
                continue
            if not batch:
                reached = total is None or origin + len(items) >= total
                return items[:max_items], reached, total
            if total is not None and origin + len(items) < total:
                url = self._page_url(path, limit, fields, origin + len(items))
                continue
            return items[:max_items], True, total
        reached = total is not None and origin + len(items) >= total
        return items[:max_items], reached, total

    def delete_endpoint(self, org_id: str, endpoint_id: str):
        org = urllib.parse.quote(org_id, safe="")
        endpoint = urllib.parse.quote(endpoint_id, safe="")
        return self._request("DELETE", f"/endpoints/managed/{org}/{endpoint}")

    def create_automation_instance(self, org_id: str, body: dict):
        """Start a one-shot automation. The body can contain a script, so callers must not log it."""
        org = urllib.parse.quote(org_id, safe="")
        return self._request("POST", f"/automations/instances/{org}", payload=body)
