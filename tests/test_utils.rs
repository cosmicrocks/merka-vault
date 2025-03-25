use log::{error, info};
use std::io;
use std::process::Command;
use std::sync::Once;

// Initialize logging once
static INIT: Once = Once::new();

/// Sets up logging for tests
pub fn setup_logging() {
    INIT.call_once(|| {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    });
}

/// Checks if the server is already running
pub async fn is_server_running() -> bool {
    // Attempt to connect to the server's status endpoint
    match reqwest::Client::new()
        .get("http://localhost:8080/api/status")
        .send()
        .await
    {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// A struct to handle the docker-compose environment
pub struct DockerComposeEnv {
    pub up_succeeded: bool,
}

impl DockerComposeEnv {
    pub fn new() -> Self {
        // Initialize
        DockerComposeEnv {
            up_succeeded: false,
        }
    }

    pub fn start(&mut self) -> io::Result<()> {
        info!("Starting docker-compose environment...");
        let output = Command::new("docker-compose")
            .arg("up")
            .arg("-d")
            .output()?;

        if output.status.success() {
            info!("Docker-compose started successfully");
            self.up_succeeded = true;
            // Wait for services to be ready
            std::thread::sleep(std::time::Duration::from_secs(3));
            Ok(())
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            error!("Failed to start docker-compose: {}", error_msg);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Docker-compose failed: {}", error_msg),
            ))
        }
    }

    pub fn stop(&self) -> io::Result<()> {
        if self.up_succeeded {
            info!("Stopping docker-compose environment...");
            let output = Command::new("docker-compose").arg("down").output()?;

            if output.status.success() {
                info!("Docker-compose stopped successfully");
                Ok(())
            } else {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Failed to stop docker-compose: {}", error_msg);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Docker-compose down failed: {}", error_msg),
                ))
            }
        } else {
            // Nothing to stop
            Ok(())
        }
    }
}

// Clean up when the struct is dropped
impl Drop for DockerComposeEnv {
    fn drop(&mut self) {
        if self.up_succeeded {
            if let Err(e) = self.stop() {
                error!("Failed to clean up docker-compose: {}", e);
            }
        }
    }
}
