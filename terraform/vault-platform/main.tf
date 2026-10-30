# terraform/vault-platform/main.tf — AppRole auth, KV v2, Transit and policies on vault-1.
# Manages: AppRole mount, KV v2, Transit engine + key, seed secrets, policies, roles.

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
    path = "../../.secrets/terraform/vault-platform.tfstate"
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
    max_lease_ttl     = "768h"
  }
}

# ── KV v2 secrets mount ────────────────────────────────────────────────────────

resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv"
  options     = { version = "2" }
  description = "Key-value v2 for booklib demo secrets"
}

# ── Transit secrets mount ──────────────────────────────────────────────────────

resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Transit secrets engine for booklib AES key"
}

# ── Transit key ────────────────────────────────────────────────────────────────

resource "vault_transit_secret_backend_key" "booklib_aes" {
  backend          = vault_mount.transit.path
  name             = "booklib-aes"
  type             = "aes256-gcm96"
  deletion_allowed = false
  exportable       = false
}

# ── Seed secrets ───────────────────────────────────────────────────────────────

resource "random_password" "api_password" {
  length  = 24
  special = false
}

resource "random_password" "api_auth_password" {
  length  = 24
  special = false
}

resource "vault_kv_secret_v2" "booklib_api" {
  mount               = vault_mount.kv.path
  name                = "booklib/api"
  delete_all_versions = false
  data_json = jsonencode({
    password = random_password.api_password.result
  })
}

resource "vault_kv_secret_v2" "booklib_api_auth" {
  mount               = vault_mount.kv.path
  name                = "booklib/api-auth"
  delete_all_versions = false
  data_json = jsonencode({
    password = random_password.api_auth_password.result
  })
}

# ── booklib policy ─────────────────────────────────────────────────────────────

resource "vault_policy" "booklib" {
  name   = "booklib-policy"
  policy = <<-POLICY
    path "kv/data/booklib/*" {
      capabilities = ["read"]
    }
    path "kv/metadata/booklib/*" {
      capabilities = ["read"]
    }
    path "transit/encrypt/booklib-aes" {
      capabilities = ["update"]
    }
    path "transit/decrypt/booklib-aes" {
      capabilities = ["update"]
    }
    path "transit/keys/booklib-aes" {
      capabilities = ["read"]
    }
  POLICY
}

# ── rotator policy ─────────────────────────────────────────────────────────────

resource "vault_policy" "rotator" {
  name   = "rotator-policy"
  policy = <<-POLICY
    path "auth/approle/login" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-booklib/role-id" {
      capabilities = ["read"]
    }
    path "auth/approle/role/krot-booklib/secret-id" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-booklib/secret-id/lookup" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-booklib/secret-id-accessor/destroy" {
      capabilities = ["create", "update"]
    }
    path "auth/approle/role/krot-booklib/secret-id-accessor/lookup" {
      capabilities = ["create", "update"]
    }
  POLICY
}

# ── krot-booklib AppRole ───────────────────────────────────────────────────────

resource "vault_approle_auth_backend_role" "booklib" {
  backend            = vault_auth_backend.approle.path
  role_name          = "krot-booklib"
  token_policies     = [vault_policy.booklib.name]
  token_type         = "service"
  token_ttl          = 768 * 3600
  token_max_ttl      = 768 * 3600
  secret_id_ttl      = 2160 * 3600
  secret_id_num_uses = 0
}

# ── krot-rotator AppRole ───────────────────────────────────────────────────────

resource "vault_approle_auth_backend_role" "rotator" {
  backend            = vault_auth_backend.approle.path
  role_name          = "krot-rotator"
  token_policies     = [vault_policy.rotator.name]
  token_type         = "service"
  token_ttl          = 768 * 3600
  token_max_ttl      = 768 * 3600
  secret_id_ttl      = 2160 * 3600
  secret_id_num_uses = 0
}

# ── Audit device ───────────────────────────────────────────────────────────────

resource "vault_audit" "file" {
  type = "file"
  options = {
    file_path = "/vault/audit/audit.log"
  }
}
