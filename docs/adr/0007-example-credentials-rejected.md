# ADR-0007: No example credential protects a running proxy

- Status: proposed
- Date: 2026-11-21
- Work Item: [DATENSCHLE-106]
- Extends: [ADR-0006](0006-veroeffentlichte-images-und-block-kennung.md) (master-key check)

## Context

ADR-0006 made the proxy refuse to start without a usable master key and
rejected every master key the repository had ever shipped (security audit M3).
Two follow-up findings and two notes from the audit rounds 3 and 4 remained:

1. **M4:** `.env.example` shipped `UI_PASSWORD=aendere-mich` and
   `DATENSCHLEUSE_DB_PASSWORD=aendere-mich-starkes-passwort`. The compose guard
   `${VAR:?}` only rejects an unset or empty value, so a user who copied the
   file unchanged started with a publicly known admin password. The repository
   compose even defaulted the database password to `datenschleuse`.
2. **L6:** when the switch `DATENSCHLEUSE_REQUIRE_MASTER_KEY` was absent, the
   code default was "off". Every shipped start path sets it, but an own wrapper
   or a pip installation running `litellm --config litellm/config.yaml`
   started without authentication and without a message.
3. **Info:** the opt-out values were documented differently in `docs/DEPLOY.md`
   (only `false`) and here (all of them).
4. **Info:** the compose wiring test recognised proxy services by three image
   names. A service with another image name would have escaped it.

What LiteLLM 1.97.0 does with the admin credentials (source read in the
installed package, and measured with a real start without Docker):

* `proxy/auth/login_utils.py:72-74`: `UI_PASSWORD` is read with
  `os.getenv("UI_PASSWORD", None)`. Only `None` falls back to the master key;
  a variable that is set but **empty** yields an empty password.
* `proxy/auth/login_utils.py:169-170`: the login compares the form values with
  `UI_USERNAME`/`UI_PASSWORD`; a match makes the caller `PROXY_ADMIN`.
* `proxy/proxy_server.py:13898` (`POST /login`) does not consult
  `DISABLE_ADMIN_UI` (the name does not occur in `proxy_server.py`; only the SSO
  routes in `management_endpoints/ui_sso.py:1010,2056,2084` and the discovery
  endpoint read it). The login needs `DATABASE_URL`
  (`login_utils.py:197`, `is not None`).

  Consequence: the login surface exists whenever a database is configured,
  also with `DISABLE_ADMIN_UI=True`. Measured: with `UI_PASSWORD=` (empty),
  `DISABLE_ADMIN_UI=True` and no database, `POST /login` with an empty password
  answers 400 "Not connected to DB!" (credentials accepted, the database step
  is next), with a wrong password 401 "Invalid credentials".

## Decision

**Where the checks live.** In the guardrail constructor, next to the master-key
check, behind the same switch. Reasons: the constructor runs on every start of
the proxy with this config (compose files, `docker run`, an operator's wrapper
with `--entrypoint`); an entrypoint wrapper would have to know the base image's
entrypoint and is skipped by `--entrypoint` (not verifiable without Docker);
the guardrail already judges the key LiteLLM actually resolved.

**What is checked** (only while the checks are on):

| Condition | Result |
|---|---|
| `DATABASE_URL` is not set | no login can be created: no check |
| `UI_PASSWORD` empty or blank | refuse (an empty admin password is an open login) |
| `UI_PASSWORD` shorter than 16 characters | refuse |
| `UI_PASSWORD` is a known example value | refuse |
| `UI_PASSWORD` unset and the UI is enabled | refuse |
| `UI_PASSWORD` unset and `DISABLE_ADMIN_UI=True` | start (LiteLLM uses the master key, which is validated) |
| the password in `DATABASE_URL` is a known example value | refuse |

The condition is the database, not `DISABLE_ADMIN_UI`, because of the
`POST /login` finding above. `DISABLE_ADMIN_UI` is read like LiteLLM reads it
(`str_to_bool`, `secret_managers/main.py`): only `true` disables, anything else
leaves the UI on. The known values are `KNOWN_PLACEHOLDER_PASSWORDS` in the
guardrail (compared after `strip().lower()`). Messages name variables and never
values. The database password is checked only against the known example
values, not for length (`MIN_UI_PASSWORD_LENGTH` applies to `UI_PASSWORD`
only): it may belong to an external database that this repository does not
control.

**Compose and `.env.example`.** The secret slots in `.env.example` are empty
(`UI_PASSWORD=`, `DATENSCHLEUSE_DB_PASSWORD=`, like the master key). The
repository compose loses the database password default; both compose files
require `UI_PASSWORD` and `DATENSCHLEUSE_DB_PASSWORD` with `:?`. The Postgres
container itself cannot run our check; its protection is the compose guard.
`tools/init-env.sh` creates a `.env` with generated values for the four secrets;
the README quick start uses it.

**The switch (L6).** `DATENSCHLEUSE_REQUIRE_MASTER_KEY` decides:

* `false`, `0`, `no`, `off` (any case, surrounding spaces ignored) are the
  explicit opt-out; the checks are off.
* Any other non-empty value switches the checks on (a typo fails closed).
* Absent or empty: on when `litellm.proxy.proxy_server` is loaded (the guardrail
  then guards a real listener), off otherwise. Unit tests and library use build
  the guardrail without that module and need no key.

The name stays for compatibility although the switch now covers all start-up
credential checks. The opt-out is documented in `docs/DEPLOY.md` and
`.env.example` with exactly these four values.

**Wiring test.** A compose service counts as a proxy when it is built from
`litellm/Dockerfile`, runs with `--config`, or mounts the guardrail module or
the `litellm/` directory. The image name plays no part. A counter-example test
shows a proxy under an unknown image name without the switch fails the check.

**Example values the repository has shipped.** Searched in the tree and with
`git log -S` over all branches (2026-11-21); each is rejected at start-up or
harmless:

| Value | Where | Disposition |
|---|---|---|
| `sk-datenschleuse-lokal` | master key (old `.env.example`, old test script default) | rejected (`KNOWN_PLACEHOLDER_MASTER_KEYS`) |
| `sk-1234` | never shipped here; the well-known example key of LiteLLM's documentation | rejected, listed because it is public |
| `sk-dein-eurouter-key` | `EUROUTER_API_KEY` in `.env.example` | rejected as master key; as the upstream key it is sent to eurouter.ai, which refuses it, and it opens nothing here |
| `sk-smoke-upstream-dummy`, `sk-e2e-local-ollama` | smoke/E2E configs | rejected as master key; upstream dummies for local test stacks |
| `aendere-mich` | `UI_PASSWORD` | rejected (`KNOWN_PLACEHOLDER_PASSWORDS`) |
| `aendere-mich-starkes-passwort` | `DATENSCHLEUSE_DB_PASSWORD` | rejected |
| `datenschleuse` | compose default of the database password | rejected as password; as user and database name it stays (a name, not a credential) |
| `hier-einen-fernet-key-eintragen` | `DATENSCHLEUSE_STATE_KEY` | harmless: it is no valid Fernet key, the QI store refuses to start with it (test) |
| `admin` | `UI_USERNAME` default | a user name, not a secret; the password decides |

## Alternatives

- **Check only in compose (`:?`).** Rejected: it cannot tell an example value
  from a real one, and it does not cover `docker run`.
- **Entrypoint wrapper in the image.** Rejected: skipped by `--entrypoint`, and
  the base image's entrypoint path cannot be verified without Docker.
- **Condition on `DISABLE_ADMIN_UI`.** Rejected: `POST /login` ignores it.
- **A strength heuristic (entropy, dictionaries).** Rejected, as in ADR-0006:
  length and a known-value list are explainable and testable; "random enough"
  is not.
- **Always on, without the opt-out.** Rejected: an operator behind an own
  gateway has a legitimate reason; the opt-out stays explicit and documented.
- **A separate switch for the UI check.** Rejected: two switches double the
  documentation and the ways to misconfigure; one switch means "no start-up
  credential checks".

## Consequences

- Easier: a user following the quick start ends up with generated credentials;
  copying `.env.example` unchanged does not start.
- Harder: **breaking for existing installs** that kept an example value
  (admin UI password, database password) or no database password in the
  repository compose; steps in `docs/DEPLOY.md`, "Beispiel-Zugangsdaten werden
  abgelehnt". A database that Postgres created with the old password keeps it;
  changing `.env` alone does not change it inside the volume.
- Own starts of LiteLLM without the switch (pip, own wrapper) now need a key.
- Not verified without a Docker daemon: image build and start, the Postgres
  container with the new `:?` guard, `up -d` on an existing installation, the
  Coolify redeploy, the real admin login against a database.
