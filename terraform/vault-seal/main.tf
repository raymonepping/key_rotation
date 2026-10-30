# terraform/vault-seal/main.tf — AppRole auth on vault-s.
# Manages: AppRole auth mount, the seal-autounseal role + policy,
# and the krot-seal-rotator role that keeps the former's secret-id fresh.

terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  backend "local" {
    path = "../../.secrets/terraform/vault-seal.tfstate"
  }
}

provider "vault" {
  # VAULT_ADDR, VAULT_TOKEN and VAULT_CACERT come from environment (scripts/tf.sh).
}

variable "network_cidr" {
  description = "CIDR of krot-internal; used to bind-secret-id AppRole roles."
  type        = string
  default     = ""
}

# ── AppRole auth mount ─────────────────────────────────────────────────────────

resource "vault_auth_backend" "approle" {
  type = "approle"
  path = "approle"
  tune {
    default_lease_ttl = "768h"
    max_lease_ttl     = "2160h"
  }
}

# ── autounseal policy ──────────────────────────────────────────────────────────

resource "vault_policy" "autounseal" {
  name   = "autounseal"
  policy = <<-POLICY
    # autounseal — on vault-s. The only thing vault-1's seal token may do.
    path "transit/encrypt/autounseal" {
      capabilities = ["update"]
    }
    path "transit/decrypt/autounseal" {
      capabilities = ["update"]
    }
  POLICY
}

# ── seal-autounseal role (used by vault-1 via the seal agent) ──────────────────

resource "vault_approle_auth_backend_role" "seal_autounseal" {
  backend            = vault_auth_backend.approle.path
  role_name          = "krot-seal-autounseal"
  token_policies     = [vault_policy.autounseal.name]
  token_type         = "service"
  token_ttl          = 768 * 3600   # 768h
  token_max_ttl      = 768 * 3600
  secret_id_ttl      = 2160 * 3600  # 2160h (~90 days)
  secret_id_num_uses = 0
}

# ── seal-rotator policy ────────────────────────────────────────────────────────

resource "vault_policy" "seal_rotator" {
  name   = "seal-rotator-policy"
  policy = <<-POLICY
    # Rotator can log in, look up, issue and destroy secret-ids for seal-autounseal.
    path "auth/approle/login" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-seal-autounseal/role-id" {
      capabilities = ["read"]
    }
    path "auth/approle/role/krot-seal-autounseal/secret-id" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-seal-autounseal/secret-id/lookup" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-seal-autounseal/secret-id-accessor/destroy" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-seal-autounseal/secret-id-accessor/lookup" {
      capabilities = ["create", "update"]
    }
  POLICY
}

# ── krot-seal-rotator role ─────────────────────────────────────────────────────

resource "vault_approle_auth_backend_role" "seal_rotator" {
  backend            = vault_auth_backend.approle.path
  role_name          = "krot-seal-rotator"
  token_policies     = [vault_policy.seal_rotator.name]
  token_type         = "service"
  token_ttl          = 768 * 3600
  token_max_ttl      = 768 * 3600
  secret_id_ttl      = 2160 * 3600
  secret_id_num_uses = 0
}
