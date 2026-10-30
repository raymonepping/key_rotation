# DESIGN.md — Key Rotation Lab

## Lineage

> vault_reference → secret_rotation → vault_goldie_locks → vault_portal → vault_pki → **key_rotation**

Each generation refines the same Durin pattern:
no static secrets in containers, every credential rotates automatically,
machines log in, humans only hand over one credential per plane.

---

## What this lab demonstrates

| Concept | How it appears |
|---|---|
| KV v2 secret versioning | `/api/demo-state` returns `kv.version`; UI shows a `pill cipher` badge |
| Transit AES-GCM encryption | `booklib-aes` key on vault-1; booklib can encrypt/decrypt without ever exporting the key |
| AppRole credential rotation | krot-rotator keeps `krot-booklib` secret-id fresh; krot-vault-agent holds a valid token at all times |
| Token-file pattern | `VAULT_TOKEN_FILE=/run/vault/token`; booklib calls `readFileSync` per request |
| Zero-secret containers | No `VAULT_TOKEN` in any `compose.yaml` environment block |
| Transit seal (auto-unseal) | vault-1 unseals itself via vault-s; vault-s uses Shamir |

---

## Vault topology

```
krot-vault-s  (OSS 2.0.4)             krot-vault-1  (ENT 2.0.4-ent)
┌──────────────────────────┐           ┌──────────────────────────────────────┐
│ Raft  Shamir seal 1/1    │──seal──►  │ Raft  Transit auto-unseal            │
│ Transit: autounseal key  │           │ KV v2 mount (kv/)                    │
│ AppRole: seal-autounseal │           │   booklib/api          ← demo secret │
│ AppRole: krot-seal-rot.  │           │   booklib/api-auth     ← API key     │
└──────────────────────────┘           │ Transit mount (transit/)             │
          ▲                            │   booklib-aes  (aes256-gcm96)        │
 krot-seal-rotator                     │ AppRole: krot-booklib                │
 krot-seal-agent ──transit-token──►    │ AppRole: krot-rotator                │
                                       └──────────────────────────────────────┘
                                                   ▲
                              krot-rotator   (rotates krot-booklib secret-id)
                              krot-vault-agent (token-file sink)
                                                   ▲
                              krot-booklib   (Node.js API)
                              krot-web       (React SPA + nginx HTTPS)
```

---

## Compose stacks

| Project | Services | Purpose |
|---|---|---|
| `krot-seal` | vault-s, seal-rotator, seal-agent | Shamir seal provider; issues Transit tokens |
| `krot-vault` | vault-1 | Application Vault; consumes seal token from `krot-seal_seal-token` volume |
| `krot-app`  | rotator, vault-agent, booklib, web | Application plane; reads from vault-1 via token file |

---

## Token chain (Durin pattern)

```
Human  ──gives──►  krot-seal-rotator  (seal plane credential in .secrets/vault/seal-rotator/)
                        │ rotates seal-autounseal secret-id on vault-s
                        ▼
               krot-seal-agent  ──logs in──►  vault-s
                        │ writes transit-token to seal-token volume
                        ▼
               krot-vault-1  ──reads token from volume at start──►  vault-s (auto-unseal)

Human  ──gives──►  krot-rotator  (app plane credential in .secrets/vault/rotator/)
                        │ rotates krot-booklib secret-id on vault-1
                        ▼
               krot-vault-agent  ──logs in──►  vault-1
                        │ writes token to agent-token volume (/run/vault/token)
                        ▼
               krot-booklib  ──reads token per request──►  vault-1 (KV, Transit)
```

---

## Daylight Glass — state map

| UI state | Pill / tone class | Description |
|---|---|---|
| KV version n | `pill cipher` | Increments on every `make rotate-demo` |
| Rotation in progress | `pill warn` | Between old and new secret-id being issued |
| Rotation complete | `pill ok` | New version confirmed in `/api/demo-state` |
| API key valid | `pill ok` | `/api/test-key` → 200 |
| API key invalid | `pill denied` | `/api/test-key` → 401 |
| Vault node active | `tone-ok` · topbar pill | `/health` → reachable + unsealed + not standby |
| Vault node sealed | `tone-denied` · topbar pill | `/health` → sealed |
| Vault node checking | `tone-warn` · topbar pill | First load / no response |

---

## Ports

| Service | Published port | Internal |
|---|---|---|
| vault-s | 18700 | 8200 |
| vault-1 | 18701 | 8200 |
| booklib API | 13400 | 3001 |
| Frontend (HTTPS) | 13401 | 8443 |

---

## First run

```sh
make env-init          # create .env
make license           # install ENT licence
make bootstrap         # everything: TLS, Vault, Terraform, images, verify
```

Or step by step:

```sh
make gen-certs
make vault-bootstrap   # init vault-s (Shamir) + vault-1 (Transit auto-unseal)
make tf-all            # Terraform: AppRoles, KV, Transit key, policies
make rotator-bootstrap # deliver the two rotator credentials
make seal-up           # start rotator + seal agent; vault-1 gets a fresh token
make vault-recreate    # switch vault-1 to the seal agent's token
make app-build         # build booklib + frontend images
make app-up            # start rotator, agent, booklib, web
make verify            # 25/25
```

---

## Day-to-day

```sh
make up          # start everything from a stopped state
make down        # stop all stacks (data kept)
make status      # container table
make vault-status
make agents-status
make rotate-demo # rotate the KV demo secret (watch the UI)
make api-test    # test API key rotation against the live stack
make verify      # re-check 25 points
make doctor      # explain any problem and name the fix
```
