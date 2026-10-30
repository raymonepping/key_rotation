# Operations

## Lifecycle

| Target | Effect |
|---|---|
| `make up` | Start vault (with unseal) + app stack |
| `make down` | Stop all stacks, keep data |
| `make vault-up` | Start vault-s → unseal → seal agent → vault-1 |
| `make app-up` | Build if missing, start rotator + agent + booklib + web |
| `make clean-slate` | DESTRUCTIVE: remove containers and volumes (prompts DELETE) |

## Credential rotation

| Target | Effect |
|---|---|
| `make rotate-demo` | Rotate the KV demo secret (version bump visible in UI) |
| `make api-test` | Test API key rotation against the live stack |
| `make rotate-now PLANE=app ROLE=krot-booklib` | Force-rotate a secret-id immediately |
| `make agents-status` | Show every machine identity end-to-end |
| `make agents-recover` | Re-issue and restart any broken identity |

## Terraform

| Target | Effect |
|---|---|
| `make tf-all` | Apply all roots (vault-seal + vault-platform) |
| `make tf-plan-all` | Plan all roots; fail if any has pending changes |
| `make tf-destroy` | Destroy all roots (prompts DESTROY) |

## Backup & restore

```sh
make backup   # Raft snapshots + .secrets tar
```

Restore: `vault operator raft snapshot restore <snap>` on each node.
