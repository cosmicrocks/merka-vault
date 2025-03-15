log_requests_level = "debug"
log_level = "debug"

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

seal "transit" {
  address         = "http://merka-vault-root:8200"  # root vault container name resolves via docker-compose networking
  key_name        = "autounseal-key"
  mount_path      = "transit/"
  disable_renewal = "false"
  tls_skip_verify = true
}

# The sub-vault must know its own API address too (if needed for logs).
api_addr = "http://127.0.0.1:8200"

ui = true
disable_mlock = true
