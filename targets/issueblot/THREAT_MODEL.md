# Threat model — IssueBlot

## Assets / entry points
Five HTTP endpoints, each taking attacker-controlled input:
- `GET /issues/search?q=` — free-text query string
- `GET /attachments/{name}` — file name from the route
- `POST /reports/export` — JSON body with `format` and `label`
- `POST /backups/restore` — raw request body (an uploaded document)
- `POST /users/register` — JSON body with `username` and `password`

## Trust boundaries
- **HTTP input → data store.** The search query flows into a database command.
- **HTTP input → filesystem.** The attachment name flows into a file path under
  a storage root.
- **HTTP input → process execution.** Export parameters flow into an external
  document-converter invocation.
- **HTTP input → object graph.** The restore body is turned back into live
  objects by a deserializer.
- **HTTP input → credential storage.** The registration password flows into a
  hashing routine whose output is persisted.

## Attacker goals
Read or write data outside intended scope, execute commands or code on the
host, read arbitrary files, or weaken stored credentials — using only crafted
HTTP requests.

## Out of scope
Authentication/session management (not implemented), rate limiting, and
transport security.

> This document names the attack surface, not the defects. Specific findings
> are recorded separately in `docs/answer-key/issueblot-bugs.md`.
