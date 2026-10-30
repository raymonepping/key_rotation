SHELL := /bin/sh

.DEFAULT_GOAL := help

# First run:  make env-init && make license && make bootstrap
# Daily:      make up / make down   (make up unseals vault-s for you)

# Compose stacks, one project each (krot-<stack>). See compose/README.md.
STACKS  := seal vault app
NETWORK := krot-internal

.PHONY: help check clock-sync status ps volumes network ports-check compose-config env-init license license-status \
	gen-certs certs-reissue certs-status trust-root trust-root-remove \
	vault-bootstrap unseal seal-up seal-down seal-token-status vault-up vault-down vault-status vault-recreate vault-login \
	tf-seal tf-platform tf-all tf-plan-all tf-destroy \
	rotator-bootstrap agents-status agents-recover rotate-now rotation-test \
	app-build app-up app-down app-rebuild open \
	rotate-demo api-test \
	up down bootstrap verify doctor backup clean-slate \
	$(addsuffix -logs,$(STACKS))

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "key_rotation — Podman + Make + Terraform\n"} \
	  /^# ── / {gsub(/─/, ""); gsub(/^# +| +$$/, ""); printf "\n%s\n", $$0} \
	  /^[a-zA-Z0-9_-]+:.*## / {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nStacks (each has <stack>-logs):\n  %s\n' "$(STACKS)"

# ── Podman ────────────────────────────────────────────────────────────────────

check: ## Verify Podman machine, compose provider, VM clock, memory and host tools
	@./scripts/podman-check.sh

status: ## Show this project's containers and network
	@podman ps -a --filter name=^krot- --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
	@podman network exists $(NETWORK) && echo '$(NETWORK): present' || echo '$(NETWORK): not created'

ps: ## List this project's containers
	@podman ps -a --filter name=^krot-

volumes: ## List this project's named volumes and whether a container uses them
	@for v in $$(podman volume ls -q --filter name=^krot-); do \
		used=$$(podman ps -a --filter volume=$$v --format '{{.Names}}' | tr '\n' ' '); \
		printf '  %-42s %s\n' "$$v" "$${used:-(unattached)}"; \
	done

network: ## (changes state) Create the krot-internal network if absent
	@./scripts/network.sh
	@echo "$(NETWORK): ready"

ports-check: ## Report host ports this stack wants that something else already holds
	@./scripts/ports-check.sh

compose-config: ## Validate every compose.yaml
	@for stack in $(STACKS); do \
		./scripts/compose.sh "$$stack" config --quiet || exit $$?; \
		echo "compose/$$stack/compose.yaml: ok"; \
	done

clock-sync: ## (changes state) Step the Podman VM's clock to the host's (after the Mac slept)
	@./scripts/clock-sync.sh

env-init: ## (changes state) Create .env from .env.example; never overwrites
	@./scripts/env-init.sh

license: ## (changes state) Install the Vault Enterprise licence: make license [LICENSE_FILE=path] [FORCE=1]
	@./scripts/license.sh

license-status: ## Is the Vault Enterprise licence file present? (never prints it)
	@./scripts/license.sh --status

define STACK_LOGS
$(1)-logs: ## Follow $(1) logs
	@./scripts/compose.sh "$(1)" logs -f
endef
$(foreach stack,$(STACKS),$(eval $(call STACK_LOGS,$(stack))))

# ── TLS ───────────────────────────────────────────────────────────────────────

gen-certs: ## (changes state) Create the lab CA and the Vault + web certificates; idempotent
	@./scripts/gen-certs.sh

certs-reissue: ## (changes state) Re-sign the certificates and SIGHUP running nodes
	@./scripts/gen-certs.sh --reissue

certs-status: ## Show issuer, expiry and SANs of the Vault certificate
	@./scripts/gen-certs.sh --status

trust-root: ## (changes state) Add the lab CA to the macOS trust store (requires sudo)
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain vault-tls/ca-chain.pem
	@echo "trust-root: lab CA trusted system-wide"

trust-root-remove: ## (changes state) Remove the lab CA from the macOS trust store (requires sudo)
	@sudo security delete-certificate -c "Key Rotation Lab CA" /Library/Keychains/System.keychain || true
	@echo "trust-root-remove: done"

# ── Vault ─────────────────────────────────────────────────────────────────────

vault-bootstrap: ## (changes state) Initialize vault-s and vault-1 on fresh volumes; idempotent
	@./scripts/vault-bootstrap.sh

unseal: ## (changes state) Unseal vault-s (idempotent); vault-1 then unseals itself via Transit
	@./scripts/vault-unseal.sh

seal-up: ## (changes state) Start vault-s, unseal it, then the seal rotator and seal agent
	@./scripts/seal-up.sh

seal-down: ## (changes state) Stop the seal stack; running nodes keep serving but cannot restart unsealed
	@./scripts/compose.sh seal stop

seal-token-status: ## Is the seal token vault-1 holds still accepted by vault-s?
	@./scripts/seal-token-status.sh

vault-up: ## (changes state) Cold start: vault-s, unseal, seal agent, then vault-1 (auto-unseal)
	@./scripts/vault-up.sh

vault-down: ## (changes state) Stop vault-1 then the seal stack (containers and volumes are kept)
	@./scripts/vault-down.sh

vault-status: ## Show both Vault nodes: container, init, seal, HA role, Raft index, version
	@./scripts/vault-status.sh

vault-recreate: ## (changes state) Recreate vault-1 on the seal agent's current token (keeps its data)
	@./scripts/vault-recreate.sh

vault-login: ## Print the export line that points your shell's vault CLI at a node: make vault-login NODE=vault-s|vault-1
	@./scripts/vault-login.sh $(or $(NODE),vault-1)

# ── Terraform ─────────────────────────────────────────────────────────────────

tf-seal: ## (changes state) Apply terraform/vault-seal (vault-s: AppRoles for the seal rotator and seal agent)
	@./scripts/tf.sh vault-seal apply

tf-platform: ## (changes state) Apply terraform/vault-platform (vault-1: KV, Transit, AppRoles, policies)
	@./scripts/tf.sh vault-platform apply

tf-all: ## (changes state) Every Terraform root in order
	@$(MAKE) --no-print-directory tf-seal
	@$(MAKE) --no-print-directory tf-platform

tf-plan-all: ## Plan every root; fails if any has pending changes
	@for r in vault-seal vault-platform; do \
		out=$$(mktemp); code=0; ./scripts/tf.sh $$r plan >$$out 2>&1 || code=$$?; \
		case $$code in \
		0) echo "$$r: No changes." ;; \
		2) echo "$$r: CHANGES PENDING" >&2; grep -E '^  [#~+-]|Plan:' $$out >&2; rm -f $$out; exit 2 ;; \
		*) cat $$out >&2; rm -f $$out; exit $$code ;; \
		esac; rm -f $$out; \
	done

tf-destroy: ## (changes state) Destroy every root in reverse order; type DESTROY to confirm
	@printf 'This removes engines, roles, AppRoles and policies. Type DESTROY: '; \
		read answer; [ "$$answer" = DESTROY ] || { echo "Aborted."; exit 1; }
	@./scripts/tf.sh vault-platform destroy
	@./scripts/tf.sh vault-seal destroy

# ── Identity ──────────────────────────────────────────────────────────────────

rotator-bootstrap: ## (changes state) Deliver the rotators' own credentials (the only ones handed over); idempotent
	@./scripts/rotator-bootstrap.sh

agents-status: ## Every machine identity: rotator, credential, secret-id expiry, agent health, token TTL
	@./scripts/agents-status.sh

agents-recover: ## (changes state) Re-deliver a rotator credential that cannot log in; restart rejected agents
	@./scripts/agents-recover.sh

rotate-now: ## (changes state) Force a secret-id rotation now: make rotate-now PLANE=seal|app ROLE=<role>
	@./scripts/rotate-now.sh "$(or $(PLANE),app)" "$(or $(ROLE),krot-booklib)"

rotation-test: ## (changes state) Self-healing tests: breaks credentials on purpose, every case must heal
	@./scripts/test-rotation.sh

# ── App ───────────────────────────────────────────────────────────────────────

app-build: ## (changes state) Build the booklib and frontend images
	@./scripts/app-build.sh $(TARGETS)

app-up: ## (changes state) Start the rotator, Vault Agent, booklib and frontend (builds if missing)
	@./scripts/app-up.sh

app-down: ## (changes state) Stop the app stack
	@./scripts/compose.sh app stop

app-rebuild: ## (changes state) Rebuild images and recreate the app services (after editing booklib/ or frontend/)
	@./scripts/app-build.sh $(TARGETS)
	@./scripts/compose.sh app up -d --force-recreate booklib web

open: ## Print the UI and Vault addresses
	@bash -c '. ./scripts/common.sh && \
		echo "Key Rotation UI: https://127.0.0.1:$$(krot_conf KROT_PORT_WEB)/" && \
		echo "Vault OSS UI:    https://localhost:$$(krot_conf KROT_PORT_VAULT_S)/ui" && \
		echo "Vault ENT UI:    https://localhost:$$(krot_conf KROT_PORT_VAULT_1)/ui"'

rotate-demo: ## (changes state) Demonstrate a KV secret rotation
	@bash -c '. ./scripts/common.sh && vault_node vault-1 && vault_root vault && \
		./booklib/scripts/secret_rotation.sh rotate'

api-test: ## Test the API key rotation against the live stack
	@bash -c '. ./scripts/common.sh && vault_node vault-1 && vault_root vault && \
		./booklib/scripts/api_rotation.sh test'

# ── Lifecycle ─────────────────────────────────────────────────────────────────

up: ## (changes state) Start everything from a stopped machine: vault (with unseal), app
	@$(MAKE) --no-print-directory vault-up
	@$(MAKE) --no-print-directory app-up

down: ## (changes state) Stop app and vault; containers and volumes are kept
	@./scripts/compose.sh app stop 2>/dev/null || true
	@$(MAKE) --no-print-directory vault-down

bootstrap: ## (changes state) First run, from zero to verified. Idempotent
	@./scripts/bootstrap.sh

# ── Tests ─────────────────────────────────────────────────────────────────────

verify: ## End-to-end 25-point check of the entire stack
	@./scripts/verify.sh

# ── Maintenance ───────────────────────────────────────────────────────────────

doctor: ## Explain what is wrong and which command fixes it (read-only)
	@./scripts/doctor.sh

backup: ## (changes state) Raft snapshots of both nodes and .secrets into backups/<timestamp>/
	@./scripts/backup.sh

clean-slate: ## (changes state) DESTRUCTIVE: remove containers and volumes, move credentials aside (backup first; type DELETE)
	@./scripts/clean-slate.sh
