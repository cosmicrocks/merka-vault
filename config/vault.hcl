log_requests_level = "debug"
log_level = "debug"

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

# Specify the API address so that external clients (and the sub vault) know where to reach Vault.
api_addr = "http://127.0.0.1:8200"

ui = true