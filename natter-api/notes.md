# Notes
## Same-Origin Policy (SSO)
S. 95
Is applied by web browsers allwoing pages or scripts loaded from one origin to interact with others.
Requests to the same origin are always allowed (but can be further restricted, too) and requests to other origins are restricted default.
Only certain requests are allowed cross-origin by default, e.g. GET, POST and HEAD and only a small amount of headers.

## Session Cookies
S. 116
The server sends a Set-Cookie header with the response to the client, containing some random token.
On subsequent requests to the same server, the browser sends the token back in a Cookie header, which the server can then look up in a token store.

`Set-Cookie: JSESSIONID=node0hwk7s0nq6wvppqh0wbs0cha91.node0;Path=/;Secure;HttpOnly`

# API sichern

## In general
- Thread-modelling with STRIDE
- Rate-limiting
- Enable HTTPS
  - Add HSTS Headers (S. 82)
- Use authentication
- Audit logging
- Access control

**More detailed actions**
- Do not expose implementation details
    - Overwrite the server header
    - do not send stack traces back to the client
- Do not process raw user input in sensitive processings
  - SQL-injection
  - not logging user input directly
- Do not reveal implementation details

## Sessions
- avoid session fixation (S. 118)
- use cookie security attributes, e.g. Secure, HttpOnly, SameSite (S.120)

