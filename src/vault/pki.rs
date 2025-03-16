//! PKI setup functions for Vault.
//!
//! This module provides functions to configure Vault as a root or intermediate PKI engine,
//! issue certificates, and create roles. Each function documents its parameters and return value.

use crate::vault::common::{auth_post, check_response};
use crate::vault::VaultError;
use reqwest::Client;
use serde_json::json;

/// Result of a PKI setup operation
#[derive(Debug, Clone)]
pub struct PkiResult {
    pub cert_chain: String,
    pub role_name: String,
}

/// Configures Vault as a root PKI engine by mounting, tuning, and generating a self-signed certificate.
///
/// # Parameters
/// - `addr`: Vault server address.
/// - `token`: Authentication token.
/// - `common_name`: The common name for the certificate.
/// - `ttl`: Time-to-live for the certificate.
///
/// # Returns
/// A certificate string on success.
pub async fn setup_pki_root(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<String, VaultError> {
    let client = Client::new();

    // Mount and tune the PKI engine at "pki".
    let mount_url = format!("{}/v1/sys/mounts/pki", addr);
    auth_post(&client, token, &mount_url, json!({ "type": "pki" })).await?;
    let tune_url = format!("{}/v1/sys/mounts/pki/tune", addr);
    auth_post(&client, token, &tune_url, json!({ "max_lease_ttl": ttl })).await?;

    // Generate a self-signed root certificate.
    let gen_url = format!("{}/v1/pki/root/generate/internal", addr);
    let gen_payload = json!({ "common_name": common_name, "ttl": ttl });
    let resp = auth_post(&client, token, &gen_url, gen_payload).await?;
    let json_resp = check_response(resp).await?;
    let cert = json_resp
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Configure issuing and CRL URLs.
    let urls_url = format!("{}/v1/pki/config/urls", addr);
    let urls_payload = json!({
        "issuing_certificates": format!("{}/v1/pki/ca", addr),
        "crl_distribution_points": format!("{}/v1/pki/crl", addr)
    });
    auth_post(&client, token, &urls_url, urls_payload).await?;

    // Create a role (role name derived from the common name).
    let role_name = common_name.replace('.', "-");
    let role_url = format!("{}/v1/pki/roles/{}", addr, role_name);
    let role_payload = json!({
        "allowed_domains": common_name,
        "allow_subdomains": true,
        "max_ttl": ttl
    });
    auth_post(&client, token, &role_url, role_payload).await?;

    Ok(cert)
}

/// Configures an intermediate PKI engine by generating a CSR and signing it using the root.
///
/// # Parameters
/// - `root_addr`: Address of the root Vault.
/// - `root_token`: Token for the root Vault.
/// - `int_addr`: Address of the intermediate Vault.
/// - `int_token`: Token for the intermediate Vault.
/// - `common_name`: Common name for the certificate.
/// - `ttl`: Time-to-live for the certificate.
///
/// # Returns
/// A tuple containing the certificate chain and the derived role name.
pub async fn setup_pki_intermediate(
    root_addr: &str,
    root_token: &str,
    int_addr: &str,
    int_token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<(String, String), VaultError> {
    let client = Client::new();

    // Get the root certificate.
    let root_cert = setup_pki_root(root_addr, root_token, common_name, ttl).await?;

    // Configure the intermediate Vault.
    let int_mount = "pki";
    let int_mount_url = format!("{}/v1/sys/mounts/{}", int_addr, int_mount);
    auth_post(&client, int_token, &int_mount_url, json!({ "type": "pki" })).await?;
    let int_tune_url = format!("{}/v1/sys/mounts/{}/tune", int_addr, int_mount);
    auth_post(
        &client,
        int_token,
        &int_tune_url,
        json!({ "max_lease_ttl": ttl }),
    )
    .await?;

    // Generate a CSR on the intermediate Vault.
    let csr_url = format!(
        "{}/v1/{}/intermediate/generate/internal",
        int_addr, int_mount
    );
    let csr_payload = json!({ "common_name": common_name, "ttl": ttl });
    let csr_resp = auth_post(&client, int_token, &csr_url, csr_payload).await?;
    let csr_json = check_response(csr_resp).await?;
    let csr = csr_json
        .get("data")
        .and_then(|d| d.get("csr"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Sign the intermediate CSR using the root Vault.
    let sign_url = format!("{}/v1/pki/root/sign-intermediate", root_addr);
    let sign_payload = json!({
        "csr": csr,
        "common_name": common_name,
        "ttl": ttl,
        "format": "pem_bundle"
    });
    let sign_resp = auth_post(&client, root_token, &sign_url, sign_payload).await?;
    let sign_json = check_response(sign_resp).await?;
    let signed_cert = sign_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Set the signed certificate on the intermediate Vault.
    let set_url = format!("{}/v1/{}/intermediate/set-signed", int_addr, int_mount);
    auth_post(
        &client,
        int_token,
        &set_url,
        json!({ "certificate": signed_cert }),
    )
    .await?;

    // Configure URLs on the intermediate Vault.
    let int_urls_url = format!("{}/v1/{}/config/urls", int_addr, int_mount);
    let int_urls_payload = json!({
        "issuing_certificates": format!("{}/v1/{}/ca", int_addr, int_mount),
        "crl_distribution_points": format!("{}/v1/{}/crl", int_addr, int_mount)
    });
    auth_post(&client, int_token, &int_urls_url, int_urls_payload).await?;

    // Create a role on the intermediate Vault.
    let role_name = format!("{}-int", common_name.replace('.', "-"));
    let role_url = format!("{}/v1/{}/roles/{}", int_addr, int_mount, role_name);
    let role_payload = json!({
        "allowed_domains": common_name,
        "allow_subdomains": true,
        "allow_bare_domains": true,
        "max_ttl": ttl
    });
    auth_post(&client, int_token, &role_url, role_payload).await?;

    let cert_chain = format!("{}\n{}", signed_cert, root_cert);
    Ok((cert_chain, role_name))
}

/// Configures PKI using two mounts on the same Vault server.
///
/// # Parameters
/// - `addr`: Vault server address.
/// - `token`: Authentication token.
/// - `common_name`: The common name for the certificate.
/// - `ttl`: Time-to-live for the certificate.
///
/// # Returns
/// A tuple of the certificate chain and role name.
pub async fn setup_pki_same_vault(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
) -> Result<(String, String), VaultError> {
    let client = Client::new();
    let mount_root = "pki_root";
    let mount_int = "pki";

    // Configure the root mount.
    let root_mount_url = format!("{}/v1/sys/mounts/{}", addr, mount_root);
    auth_post(&client, token, &root_mount_url, json!({ "type": "pki" })).await?;
    let tune_root_url = format!("{}/v1/sys/mounts/{}/tune", addr, mount_root);
    auth_post(
        &client,
        token,
        &tune_root_url,
        json!({ "max_lease_ttl": ttl }),
    )
    .await?;
    let root_url = format!("{}/v1/{}/root/generate/internal", addr, mount_root);
    let root_payload = json!({ "common_name": common_name, "ttl": ttl });
    let root_resp = auth_post(&client, token, &root_url, root_payload).await?;
    let root_json = check_response(root_resp).await?;
    let root_cert = root_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let root_urls_url = format!("{}/v1/{}/config/urls", addr, mount_root);
    auth_post(
        &client,
        token,
        &root_urls_url,
        json!({
            "issuing_certificates": format!("{}/v1/{}/ca", addr, mount_root),
            "crl_distribution_points": format!("{}/v1/{}/crl", addr, mount_root)
        }),
    )
    .await?;

    // Configure the intermediate mount.
    let int_mount_url = format!("{}/v1/sys/mounts/{}", addr, mount_int);
    auth_post(&client, token, &int_mount_url, json!({ "type": "pki" })).await?;
    let tune_int_url = format!("{}/v1/sys/mounts/{}/tune", addr, mount_int);
    auth_post(
        &client,
        token,
        &tune_int_url,
        json!({ "max_lease_ttl": ttl }),
    )
    .await?;
    let csr_url = format!("{}/v1/{}/intermediate/generate/internal", addr, mount_int);
    let csr_payload = json!({ "common_name": common_name, "ttl": ttl });
    let csr_resp = auth_post(&client, token, &csr_url, csr_payload).await?;
    let csr_json = check_response(csr_resp).await?;
    let csr = csr_json
        .get("data")
        .and_then(|d| d.get("csr"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let sign_url = format!("{}/v1/{}/root/sign-intermediate", addr, mount_root);
    let sign_payload = json!({
        "csr": csr,
        "common_name": common_name,
        "ttl": ttl,
        "format": "pem_bundle"
    });
    let sign_resp = auth_post(&client, token, &sign_url, sign_payload).await?;
    let sign_json = check_response(sign_resp).await?;
    let signed_cert = sign_json
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let set_url = format!("{}/v1/{}/intermediate/set-signed", addr, mount_int);
    auth_post(
        &client,
        token,
        &set_url,
        json!({ "certificate": signed_cert }),
    )
    .await?;
    let int_urls_url = format!("{}/v1/{}/config/urls", addr, mount_int);
    auth_post(
        &client,
        token,
        &int_urls_url,
        json!({
            "issuing_certificates": format!("{}/v1/{}/ca", addr, mount_int),
            "crl_distribution_points": format!("{}/v1/{}/crl", addr, mount_int)
        }),
    )
    .await?;
    let role_name = common_name.replace('.', "-");
    let role_url = format!("{}/v1/{}/roles/{}", addr, mount_int, role_name);
    auth_post(
        &client,
        token,
        &role_url,
        json!({
            "allowed_domains": common_name,
            "allow_subdomains": true,
            "max_ttl": ttl
        }),
    )
    .await?;
    let cert_chain = format!("{}\n{}", signed_cert, root_cert);
    Ok((cert_chain, role_name))
}

/// Wrapper for PKI setup that selects the correct mode.
///
/// - If `intermediate` is false, uses root‑only setup.
/// - If true and an intermediate address is provided, uses separate intermediate mode.
/// - Otherwise, uses same‑vault mode.
///
/// # Parameters
/// - `addr`: Vault server address.
/// - `token`: Authentication token.
/// - `common_name`: Certificate common name.
/// - `ttl`: Time-to-live for the certificate.
/// - `intermediate`: Whether to use intermediate mode.
/// - `intermediate_addr`: Optional address for the intermediate Vault.
/// - `int_token`: Optional token for the intermediate Vault.
///
/// # Returns
/// A tuple with the certificate (or chain) and the PKI role name.
pub async fn setup_pki(
    addr: &str,
    token: &str,
    common_name: &str,
    ttl: &str,
    intermediate: bool,
    intermediate_addr: Option<&str>,
    int_token: Option<&str>,
) -> Result<(String, String), VaultError> {
    if !intermediate {
        let cert = setup_pki_root(addr, token, common_name, ttl).await?;
        let role_name = common_name.replace('.', "-");
        Ok((cert, role_name))
    } else if let Some(int_addr) = intermediate_addr {
        if let Some(itoken) = int_token {
            setup_pki_intermediate(addr, token, int_addr, itoken, common_name, ttl).await
        } else {
            Err(VaultError::Api(
                "Intermediate setup requires both address and token".into(),
            ))
        }
    } else {
        setup_pki_same_vault(addr, token, common_name, ttl).await
    }
}

/// Issues a certificate from the PKI engine using the specified role.
///
/// # Parameters
/// - `addr`: Vault server address.
/// - `token`: Authentication token.
/// - `role_name`: Role to use for issuing the certificate.
/// - `common_name`: The common name for the certificate.
/// - `ttl`: Optional time-to-live for the certificate; defaults to "1h" if not provided.
///
/// # Returns
/// A tuple containing the full certificate chain and the private key.
pub async fn issue_certificateificate(
    addr: &str,
    token: &str,
    role_name: &str,
    common_name: &str,
    ttl: Option<&str>,
) -> Result<(String, String), VaultError> {
    let default_ttl = ttl.unwrap_or("1h");
    let url = format!("{}/v1/pki/issue/{}", addr, role_name);
    let payload = json!({
        "common_name": common_name,
        "ttl": default_ttl
    });
    let client = Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&payload)
        .send()
        .await?;
    let json_resp = check_response(resp).await?;

    let certificate = json_resp
        .get("data")
        .and_then(|d| d.get("certificate"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultError::Api("No certificate in response".into()))?
        .to_string();

    let full_chain = if let Some(ca_chain) = json_resp
        .get("data")
        .and_then(|d| d.get("ca_chain"))
        .and_then(|v| v.as_array())
    {
        let mut chain = certificate.clone();
        for ca in ca_chain {
            if let Some(ca_str) = ca.as_str() {
                chain.push('\n');
                chain.push_str(ca_str);
            }
        }
        chain
    } else if let Some(issuing_ca) = json_resp
        .get("data")
        .and_then(|d| d.get("issuing_ca"))
        .and_then(|v| v.as_str())
    {
        format!("{}\n{}", certificate, issuing_ca)
    } else {
        certificate.clone()
    };

    let issued_key = json_resp
        .get("data")
        .and_then(|d| d.get("private_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultError::Api("No private key in response".into()))?
        .to_string();

    Ok((full_chain, issued_key))
}
