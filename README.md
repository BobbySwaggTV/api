<p align="center">
  <img width="686" height="200" alt="15th MEU API logo" src="https://github.com/user-attachments/assets/0674cc53-cb8d-4a8a-ad5e-331945ce1f4b" />
</p>
# 15th MEU API

An HTTP/JSON API that serves 15th MEU community and roster data. It is a read
layer over the forum's MySQL database, written in Go on the standard
library `net/http` stack.

Repository: [BobbySwaggTV/api](https://github.com/BobbySwaggTV/api), branch
`feature/15th-meu`. The community forum is [15th MEU](https://15thmeu.org).

## Clients

### Authentication

The API is guarded by a `Bearer` token. Tokens are issued and managed in
the forum admin UI; each one carries a set of scopes that gate which parts
of the surface it can read. Send it on every request:

```
Authorization: Bearer <your token>
```

### HTTP/JSON

The interactive documentation lives at [api.15thmeu.org](https://api.15thmeu.org).

> To try the API from the docs page, click the `Authorize` button at the
> top and paste your bearer token.

Wrap the requests in whichever language or HTTP client you prefer.

#### NodeJS

```js
const axios = require('axios');
const token = "<your token>";

const client = axios.create({
  baseURL: 'https://api.15thmeu.org/api/v1',
  withCredentials: false,
  headers: {
    Accept: 'application/json',
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`
  }
});

client.get("milpacs/profile/id/1")
    .then(res => {
        console.log(res.data)
    });
```

#### Go

```go
package main

import (
    "context"
    "fmt"
    "golang.org/x/oauth2"
)

func main() {
    ctx := context.Background()
    client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{
        AccessToken: "<your token>",
        TokenType:   "Bearer",
    }))

    res, err := client.Get("https://api.15thmeu.org/api/v1/milpacs/profile/id/1")
    if err != nil {
        panic(err)
    }
    fmt.Println(res)
}
```

## Architecture

The service runs as a single public listener that serves the whole `/api`
surface plus the documentation UI. There is no second port and no gRPC: an
earlier version split the process into a gRPC server and a generated
HTTP/JSON gateway, but that design was retired in upstream [PRD #112][prd]
("Goodbye gRPC"). See [ADR 0006][adr6] for why.

The contract is checked into the repo, not generated:

- the **types package** (`types/`) holds the hand-written wire types;
- the **OpenAPI 3.1 spec** (`openapi/openapi.yaml`) is the reference
  document served at the docs URL;
- the **golden corpus** (`contract/goldens/`) records one
  request/response per public route.

`contract/spec_test.go` validates the spec against the corpus in both
directions, so the three stay in step and any drift fails CI naming the
operation and field. The domain glossary and the add-an-endpoint checklist
live in [`CONTEXT.md`](CONTEXT.md).

[prd]: https://github.com/7Cav/api/issues/112
[adr6]: docs/adr/0006-single-listener-net-http-and-hand-owned-openapi.md

## Running

In production the API runs behind an nginx that terminates TLS in front of
the single HTTP listener. The `docker-compose.yaml` in this repo is a
prod-shaped template; the live compose file is customized and kept out of
the repo.

You need a copy of the 15th MEU XenForo database reachable from the container
(see the `DB_*` environment variables in `docker-compose.yaml`). Then:

```shell
docker compose up -d
```

## Development

With Go 1.25.10 or newer installed you can build and run the API directly. There is no code
generation or tooling install step:

```shell
git clone --branch feature/15th-meu https://github.com/BobbySwaggTV/api.git
cd api
go mod download
go build ./...
go run main.go serve
```

`go run main.go serve` needs the database environment variables set (see
`docker-compose.yaml` for the full list). Set `DB_HOST`, `DB_PORT`,
`DB_USERNAME`, `DB_PASSWORD`, and `DB_NAME` for a local development database,
and `FORUM_BASE_URL=https://15thmeu.org` for forum links. The HTTP listener
is on port 11000; local interactive docs are at http://localhost:11000.
The compose template builds the local `15th-meu-api:latest` image and expects
the external networks and database described in its prerequisites.

### Tests

```shell
go test ./...          # unit + contract suite, no external services
make test-integration  # adds the dockerized MariaDB harness (testdb/)
```

`make lint` runs `go vet`. The contract suite (`contract/`) replays the
golden corpus against the live stack and validates the OpenAPI spec; run it
before pushing changes that touch the wire surface.

### Adding an endpoint

Wire types → handler → route registration → spec operation → goldens. The
spec and golden steps are CI-enforced. The full checklist is in
[`CONTEXT.md`](CONTEXT.md); the in-code long form is in the package docs of
`rest/rest.go` and `types/types.go`.

## Upstream attribution and migration status

This project derives from [7Cav API](https://github.com/7Cav/api). Original
copyright and GPL notices are retained; see [LICENSE](LICENSE). Historical
architecture decisions retain upstream references. The `15meu_` API-key
prefix and the `xf_15meu_*` table names are the live 15th MEU identifiers;
the `meu15_`-prefixed and unbranded fixture keys exist only to pin
that the bearer token's prefix is branding, not part of authentication.

The release workflow builds the `15th-meu-api` image but does not publish
it: no 15th MEU container registry or deployment watcher has been
configured yet, and the pipeline must not push to the upstream 7Cav
infrastructure. Publishing stays disabled until a 15th MEU target exists.

The reservist position group is matched brand-neutrally (any group title
containing `Reserv` maps to `Reserve`), so no organization-specific title
is hardcoded while the 15th MEU's own group naming is being established.
