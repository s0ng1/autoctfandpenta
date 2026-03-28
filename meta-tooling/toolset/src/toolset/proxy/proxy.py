import base64
import time
from typing import Annotated, Any
from urllib.parse import urlsplit, urlunsplit

import requests
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

from core import tool, toolset, namespace

namespace()

@toolset()
class Proxy:
    def __init__(self, url: str, token: str):
        transport = RequestsHTTPTransport(url=url, headers={'Authorization': f'Bearer {token}'})
        self.__client = Client(transport=transport)

    @tool()
    def official_methods(self) -> dict:
        """
        Return the officially supported proxy methods so agents do not guess API names.
        """
        return {
            "preferred_methods": [
                "list_traffic",
                "view_traffic",
                "replay_request",
            ],
            "compatibility_aliases": {
                "get_traffic": "list_traffic",
            },
            "notes": [
                "Use list_traffic to enumerate recent matching requests.",
                "Use view_traffic to inspect one request/response pair by id.",
                "Use replay_request to resend a captured request with optional overrides.",
            ],
        }

    @tool()
    def list_traffic(self, limit: int=5, offset: int=0, filter: Annotated[str, '''Caido HTTPQL statement, such as ' req.host.like:"%.example.com" and req.method.like:"POST" ' ''']=None) -> dict:
        query = gql("""
            query($offset: Int, $limit: Int, $filter: HTTPQL) {
              interceptEntriesByOffset(
                limit: $limit
                offset: $offset
                filter: $filter
                order: {by: REQ_CREATED_AT, ordering: DESC}
              ) {
                count {
                  value
                }
                nodes {
                  request {
                    id
                    createdAt
                    host
                    port
                    method
                    path
                    query
                    length
                    response {
                      length
                      roundtripTime
                      statusCode
                    }
                  }
                }
              }
            }
        """)
        if filter:
            filter = f"{filter} and preset:no-images and preset:no-styling"
        else:
            filter = "preset:no-images and preset:no-styling"
        result = self.__client.execute(query, variable_values={"limit": limit, "offset": offset, "filter": filter})
        return result['interceptEntriesByOffset']

    @tool()
    def get_traffic(
        self,
        limit: int = 5,
        offset: int = 0,
        filter: Annotated[str, '''Deprecated alias for list_traffic. Use the same HTTPQL filter syntax as list_traffic. '''] = None,
    ) -> dict:
        """
        Deprecated compatibility alias for list_traffic.
        """
        result = self.list_traffic(limit=limit, offset=offset, filter=filter)
        if isinstance(result, dict):
            result = dict(result)
            result.setdefault(
                "_compat",
                {
                    "deprecated_method": "get_traffic",
                    "replacement": "list_traffic",
                },
            )
        return result

    @tool()
    def view_traffic(self, id: int, b64encode: Annotated[bool, "whether the returned traffic needs to be base64 encoded. Generally, not required, so you can view the results directly"] = False) -> dict:
        query = gql("""
            query ($id: ID!) {
              request(id: $id) {
                id
                isTls
                host
                port
                raw
                response {
                    roundtripTime
                    raw
                }
              }
            }
        """)
        result = self.__client.execute(query, variable_values={"id": str(id)})
        if not b64encode and result['request'] and 'raw' in result['request']:
            result['request']['raw'] = base64.b64decode(result['request']['raw']).decode('utf-8', errors='replace')
            if result['request']['response'] and 'raw' in result['request']['response']:
                result['request']['response']['raw'] = base64.b64decode(result['request']['response']['raw']).decode('utf-8', errors='replace')
        return result

    def _parse_raw_http_request(self, raw_request: str) -> dict[str, Any]:
        head, _, body = raw_request.partition("\r\n\r\n")
        if not _:
            head, _, body = raw_request.partition("\n\n")
        lines = [line for line in head.splitlines() if line.strip()]
        if not lines:
            raise ValueError("request raw data is empty")

        request_line = lines[0].strip()
        try:
            method, target, _version = request_line.split(maxsplit=2)
        except ValueError as exc:
            raise ValueError(f"invalid HTTP request line: {request_line}") from exc

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

        return {"method": method, "target": target, "headers": headers, "body": body}

    def _build_replay_url(self, request_info: dict[str, Any], parsed_request: dict[str, Any]) -> str:
        scheme = "https" if request_info.get("isTls") else "http"
        host = request_info.get("host") or parsed_request["headers"].get("Host", "")
        port = request_info.get("port")
        target = parsed_request["target"]

        if target.startswith("http://") or target.startswith("https://"):
            split = urlsplit(target)
            scheme = split.scheme
            host = split.hostname or host
            port = split.port or port
            path = urlunsplit(("", "", split.path, split.query, split.fragment))
        else:
            path = target

        default_port = 443 if scheme == "https" else 80
        netloc = host if not port or int(port) == default_port else f"{host}:{port}"
        return f"{scheme}://{netloc}{path}"

    def _prepare_replay_headers(self, headers: dict[str, str], body: str, overrides: dict[str, Any]) -> tuple[dict[str, str], str]:
        replay_headers = dict(headers)
        override_headers = overrides.get("headers", {}) if overrides else {}
        for key, value in override_headers.items():
            replay_headers[key] = value

        body = overrides.get("body", body) if overrides else body
        for transient in ("Host", "Content-Length", "Transfer-Encoding", "Connection"):
            replay_headers.pop(transient, None)
        return replay_headers, body

    @tool()
    def replay_request(self, request_id: str, overrides: dict = None) -> dict:
        """
        Replay one captured request with optional method/url/header/body overrides.
        """
        overrides = overrides or {}
        request_payload = self.view_traffic(id=request_id, b64encode=False).get("request")
        if not request_payload:
            raise ValueError(f"request not found: {request_id}")

        parsed_request = self._parse_raw_http_request(request_payload.get("raw", ""))
        method = overrides.get("method", parsed_request["method"])
        url = overrides.get("url") or self._build_replay_url(request_payload, parsed_request)
        headers, body = self._prepare_replay_headers(parsed_request["headers"], parsed_request["body"], overrides)
        timeout = overrides.get("timeout", 30)

        start = time.perf_counter()
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body.encode("utf-8") if isinstance(body, str) else body,
            timeout=timeout,
            allow_redirects=overrides.get("allow_redirects", True),
            verify=overrides.get("verify", True),
        )
        duration_ms = int((time.perf_counter() - start) * 1000)

        body_preview = response.text[:1000]
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body_preview": body_preview,
            "duration_ms": duration_ms,
        }


if __name__ == "__main__":
    from . import proxy
    proxy.list_traffic()
