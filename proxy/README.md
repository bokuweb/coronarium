# `bokuweb/sakimori/proxy`

Run `sakimori proxy` as a GitHub Actions background service so every
HTTPS request from subsequent steps in the job is filtered through
it: too-young versions of crates.io / npm / pypi / nuget packages
are invisible to the resolver — the pnpm-style
`minimumReleaseAge` auto-fallback for every ecosystem.

Works on Linux, macOS, and Windows GitHub-hosted runners. The
process keeps running until the post-step (end of job) kills it.

## Quick start (minimumReleaseAge only)

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bokuweb/sakimori/proxy@v0
        with:
          min-age: 7d
      - run: npm ci
```

Subsequent steps in the same job see `HTTPS_PROXY` / `HTTP_PROXY`
plus per-tool CA bundle env vars (`CARGO_HTTP_CAINFO`, `PIP_CERT`,
`NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`) set
by the action — nothing else is required to route traffic through
the proxy.

## Hub upload (optional)

The proxy can also POST every allowed install to a self-hosted
[`sakimori-hub`](https://github.com/bokuweb/sakimori-hub) endpoint
for team-wide visibility into what package versions landed on CI
runners. The hub side accepts `InstallEventBatch` JSON at
`POST /v1/{team}/_team|_user|{project}/events` with `Authorization:
Bearer <token>`.

Mint a token in the hub UI (or via its `POST /api/v1/teams/{slug}/tokens/{user|team}`
API), store the plaintext as a **repository secret** (e.g.
`SAKIMORI_TOKEN`), and the URL as a **repository variable**
(`SAKIMORI_INGEST_URL`):

```yaml
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: bokuweb/sakimori/proxy@v0
        with:
          min-age: 7d
          ingest-url:   ${{ vars.SAKIMORI_INGEST_URL }}
          ingest-token: ${{ secrets.SAKIMORI_TOKEN }}
      - run: npm ci
```

The token is registered with the GitHub Actions log scrubber via
`::add-mask::` before it ever touches the proxy's environment, so
any later step that echoes it (`set -x` traces, proxy stdout,
spawn-error dumps) renders the bytes as `***` in the workflow log.
Use `${{ secrets.* }}` — never inline the token in the workflow
YAML.

Setting only one of `ingest-url` / `ingest-token` is a no-op; the
action surfaces a `::notice::` so the misconfiguration is visible.

### Fork PR caveat

GitHub does not expose repository secrets to workflow runs
triggered by a fork-based PR. Hub upload is expected to be
disabled in that case — both the token and (if you stored it
as a secret rather than a variable) the URL will be empty, and
the action's notice paths above make that explicit.

## Inputs

| Input             | Default                   | Description |
|-------------------|---------------------------|-------------|
| `min-age`         | `7d`                      | Minimum package age. Versions younger than this are invisible to the resolver. |
| `listen`          | `127.0.0.1:8910`          | Address the proxy listens on. |
| `fail-on-missing` | `false`                   | Treat unknown publish dates as a deny. Default fails open (allow through) so a flaky registry doesn't brick the build. |
| `version`         | `v0`                      | sakimori release tag to download. |
| `token`           | `${{ github.token }}`     | GitHub token for `gh release download`. |
| `ingest-url`      | `""`                      | Optional sakimori-hub ingest endpoint (see above). |
| `ingest-token`    | `""`                      | Bearer credential for `ingest-url`. Treat as a secret. |

## Outputs

| Output    | Description |
|-----------|-------------|
| `ca-cert` | Absolute path to the proxy's root CA PEM. |

## Limits

`sakimori run` (the eBPF audit/block supervisor) does **not** emit
install events. Hub upload only fires from the proxy decision path
— if you want hub coverage, you need to actually route installs
through this action. A `sakimori install upload` post-hoc batch
uploader for the local `installs.jsonl` written by the proxy is on
the roadmap; it would let workflows that already use the proxy
upload at end-of-job rather than per-install.
