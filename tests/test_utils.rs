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
    reqwest::Client::new()
        .get("http://localhost:8080/api/status")
        .send()
        .await
        .is_ok()
}

/// A struct to handle the docker-compose environment
pub struct DockerComposeEnv {
    pub up_succeeded: bool,
    pub start_attempted: bool,
}

impl Default for DockerComposeEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl DockerComposeEnv {
    pub fn new() -> Self {
        // Initialize
        DockerComposeEnv {
            up_succeeded: false,
            start_attempted: false,
        }
    }

    pub fn start(&mut self) -> io::Result<()> {
        info!("Starting docker-compose environment...");
        self.start_attempted = true;

        // Force cleanup of any existing containers first
        let cleanup_output = Command::new("docker-compose").arg("down").output();

        if let Err(e) = cleanup_output {
            info!("Initial cleanup warning (not critical): {}", e);
        }

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
        if self.start_attempted {
            info!("Stopping docker-compose environment...");
            let output = Command::new("docker-compose").arg("down").output()?;

            if output.status.success() {
                info!("Docker-compose stopped successfully");
                Ok(())
            } else {
                let error_msg = String::from_utf8_lossy(&output.stderr);
                error!("Failed to stop docker-compose: {}", error_msg);

                // Try a more aggressive cleanup if the normal stop fails
                let force_output = Command::new("docker-compose")
                    .arg("down")
                    .arg("--volumes")
                    .arg("--remove-orphans")
                    .output();

                if let Ok(force_result) = force_output {
                    if force_result.status.success() {
                        info!("Docker-compose force-stopped successfully");
                        return Ok(());
                    }
                }

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
        if self.start_attempted {
            info!("Cleaning up Docker from Drop implementation");

            // First try normal cleanup
            if let Err(e) = self.stop() {
                error!("Failed to clean up docker-compose: {}", e);

                // If normal cleanup fails, try more aggressive approach
                let _ = Command::new("docker-compose")
                    .arg("down")
                    .arg("--volumes")
                    .arg("--remove-orphans")
                    .output();

                // As a last resort, try to remove specific containers directly
                let _ = Command::new("docker")
                    .args(["rm", "-f", "merka-vault-root", "merka-vault-sub"])
                    .output();

                // Finally run docker system prune to clean up any remaining resources
                let prune_output = Command::new("docker")
                    .args(["system", "prune", "-f"])
                    .output();

                match prune_output {
                    Ok(output) => {
                        if output.status.success() {
                            info!("Docker system prune completed successfully");
                        } else {
                            let error_msg = String::from_utf8_lossy(&output.stderr);
                            error!("Docker system prune failed: {}", error_msg);
                        }
                    }
                    Err(e) => {
                        error!("Failed to run docker system prune: {}", e);
                    }
                }
            }

            // Wait a bit to ensure containers are fully stopped
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
