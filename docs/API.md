# Local API

The application serves a local-only HTTP API on `127.0.0.1`. The port is
printed at startup and can be selected with `--port`.

All API requests must include the random token that is embedded in the UI as:

```html
<meta name="scanner-token" content="...">
```

Send it as the `X-Scanner-Token` header. Requests are also rejected unless the
`Host` header is loopback (`127.0.0.1`, `localhost` or `::1`) and any
`Origin` header matches the request host.

Examples below assume the server is running on `127.0.0.1:8080`.

## Health

```http
GET /api/health
```

No token is required.

Example response:

```json
{
  "apiVersion": 1,
  "version": "1.3.0",
  "fixedVersions": {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12"
  },
  "cves": [
    "CVE-2026-109618",
    "CVE-2026-109619",
    "CVE-2026-115560"
  ],
  "advisories": [
    {
      "cve": "CVE-2026-115560",
      "title": "session.upload_progress",
      "severity": "low",
      "recommendation": "session.upload_progress.enabled = Off"
    }
  ]
}
```

## Start a scan

```http
POST /api/scan
Content-Type: application/json
X-Scanner-Token: <token>
```

Request body:

```json
{
  "targets": [
    "https://example.com",
    "example.org"
  ],
  "options": {
    "timeoutSeconds": 10,
    "concurrency": 5,
    "delayMs": 250,
    "maxRetries": 2,
    "followRedirects": true,
    "insecureTls": false,
    "deepCheck": true,
    "userAgent": "PHP2ShellChecker/1.3.0 (defensive vulnerability check)",
    "proxyUrl": "",
    "headers": {
      "Authorization": "Bearer example"
    },
    "cookies": {
      "session": "example"
    }
  }
}
```

Limits and defaults:

| Option | Default | Range |
| --- | --- | --- |
| `timeoutSeconds` | 10 | 2–120 |
| `concurrency` | 5 | 1–32 |
| `delayMs` | 250 | 0–10000 |
| `maxRetries` | 2 | 0–5 |
| `followRedirects` | false unless set | boolean |
| `insecureTls` | false unless set | boolean |
| `deepCheck` | false unless set | boolean |
| `userAgent` | application default | max 512 bytes |
| `headers` | empty | object of request headers |
| `cookies` | empty | object of cookie name/value pairs |
| `proxyUrl` | environment proxy | `http://`, `https://`, `direct`, `none`, `env` or empty |

`maxRetries` applies to HTTP `429` and `503` responses. The scanner honours
`Retry-After` (seconds or HTTP date) and otherwise uses exponential backoff
starting at 500 ms, capped at 10 seconds. `Retry-After` values are capped at
30 seconds.

Reserved/hop-by-hop request headers such as `Host`, `Content-Length`,
`Connection` and `Transfer-Encoding` are dropped. Invalid header names, CR/LF
values and invalid cookie pairs are also dropped. Header and cookie values are
never echoed into result evidence.

The request body is limited to 5 MiB and at most 10,000 unique targets are
accepted.

The response is `application/x-ndjson`. Each line is one JSON event:

```json
{"type":"start","total":2}
{"type":"result","result":{"input":"https://example.com","verdict":"safe", "...": "..."}}
{"type":"done","scanned":2,"elapsedMs":1234}
```

`result` contains the same fields as the UI/JSON export, including:

- `phpVersion`, `versionSource`, `verdict`, `fixedIn`
- `versionCandidates` — every observed version with `source` and `confidence`
- `deepChecks` — each extra probe with `url`, `statusCode`, optional
  `phpVersion` and `error`
- evidence fields such as `remoteIp`, `bodySha256` and `responseHeaders`

JSON exports from the UI include `schemaVersion: 1` so downstream consumers can
handle future format changes explicitly.

Abort the request to cancel the scan. The server stops scheduling new targets
when the client disconnects.

## Shut down

```http
POST /api/shutdown
X-Scanner-Token: <token>
```

Returns `204 No Content` and closes the local server.

## Example

```bash
TOKEN="$(curl -fsS http://127.0.0.1:8080/ |
  sed -n 's/.*name="scanner-token" content="\([^"]*\)".*/\1/p')"

curl -fsS -N \
  -H "Content-Type: application/json" \
  -H "X-Scanner-Token: $TOKEN" \
  -d '{"targets":["https://example.com"],"options":{"deepCheck":true}}' \
  http://127.0.0.1:8080/api/scan
```

## Status codes

| Code | Meaning |
| --- | --- |
| 200 | Scan stream started |
| 204 | Shutdown accepted |
| 400 | Invalid JSON, no targets or invalid scan options |
| 403 | Missing/wrong token, non-loopback Host or foreign Origin |
| 405 | Wrong HTTP method |
| 415 | Scan request is not `application/json` |

The API is intended for the bundled UI and local automation. It is not a
public service and must not be exposed on a network interface.
