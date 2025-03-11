//! Client implementation for Vault API interactions.
//!
//! This module provides a client for making HTTP requests to the Vault API
//! with appropriate authentication and error handling.

use crate::vault::VaultError;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method,
};
use serde_json::{json, Value};
use std::str::FromStr;
use std::time::Duration;
use tracing::{debug, info};

/// Client for interacting with the Vault HTTP API.
pub struct VaultClient {
    /// Base URL of the Vault server
    pub addr: String,
    /// Auth token for Vault API requests
    pub token: String,
    /// HTTP client for making requests
    client: Client,
    /// Custom headers to add to requests
    custom_headers: HeaderMap,
}

impl VaultClient {
    /// Creates a new VaultClient with the specified address and token.
    pub fn new(addr: &str, token: &str) -> Result<Self, VaultError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| VaultError::Network(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            addr: addr.to_string(),
            token: token.to_string(),
            client,
            custom_headers: HeaderMap::new(),
        })
    }

    /// Adds a custom header to the client.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the header
    /// * `value` - The value of the header
    pub fn add_header(&mut self, name: &str, value: &str) -> &mut Self {
        if let (Ok(header_name), Ok(header_value)) =
            (HeaderName::from_str(name), HeaderValue::from_str(value))
        {
            self.custom_headers.insert(header_name, header_value);
        }
        self
    }

    /// Makes a GET request to the Vault API.
    pub async fn get(&self, path: &str) -> Result<Value, VaultError> {
        self.request(Method::GET, path, None).await
    }

    /// Makes a POST request to the Vault API with a JSON body.
    pub async fn post_with_body(&self, path: &str, body: Value) -> Result<Value, VaultError> {
        self.request(Method::POST, path, Some(body)).await
    }

    /// Makes a PUT request to the Vault API with a JSON body.
    pub async fn put_with_body(&self, path: &str, body: Value) -> Result<Value, VaultError> {
        self.request(Method::PUT, path, Some(body)).await
    }

    /// Makes a DELETE request to the Vault API.
    pub async fn delete(&self, path: &str) -> Result<Value, VaultError> {
        self.request(Method::DELETE, path, None).await
    }

    /// Makes a request to the Vault API with the specified method and optional body.
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, VaultError> {
        let url = format!("{}{}", self.addr, path);
        let mut request = self.client.request(method, &url);

        // Add token header for authentication
        request = request.header("X-Vault-Token", &self.token);

        // Add any custom headers
        for (name, value) in self.custom_headers.iter() {
            request = request.header(name, value);
        }

        // Add JSON body if provided
        if let Some(json_body) = body {
            request = request.json(&json_body);
        }

        let response = request
            .send()
            .await
            .map_err(|e| VaultError::Network(format!("Request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(VaultError::HttpStatus(status.as_u16(), error_text));
        }

        // Return an empty JSON object for 204 No Content responses
        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(json!({}));
        }

        response
            .json::<Value>()
            .await
            .map_err(|e| VaultError::ParseError(format!("Failed to parse response: {}", e)))
    }
}
