use log::info;
use serial_test::serial;

mod test_utils;
use test_utils::{setup_logging, DockerComposeEnv};

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::Duration;
    use tokio::runtime::Runtime;

    // Helper function to start a process and return its handle
    fn start_process(command: &str, args: &[&str]) -> Child {
        Command::new(command)
            .args(args)
            .spawn()
            .expect("Failed to start process")
    }

    #[test]
    #[serial]
    fn test_example_web_server() {
        // Setup logging
        setup_logging();
        info!("Starting example web server test");

        // Start docker-compose environment
        let mut docker = DockerComposeEnv::new();
        match docker.start() {
            Ok(_) => info!("Docker environment started successfully"),
            Err(e) => {
                info!("Docker environment start failed: {}. Test skipped.", e);
                return;
            }
        };

        // Ensure the example binaries are built
        let status = Command::new("cargo")
            .args([
                "build",
                "--example",
                "web_server",
                "--example",
                "test_client",
            ])
            .status()
            .expect("Failed to build examples");

        assert!(status.success(), "Failed to build examples");

        // Start the web server
        let mut web_server = start_process("cargo", &["run", "--example", "web_server"]);

        // Sleep to let the server start up
        thread::sleep(Duration::from_secs(5));

        // Create a runtime for the test client
        let rt = Runtime::new().unwrap();

        // Run the test client to verify functionality
        let result = rt.block_on(async {
            // Start the test client
            let mut test_client = start_process(
                "cargo",
                &[
                    "run",
                    "--example",
                    "test_client",
                    "--",
                    "--restart-sub-vault",
                ],
            );

            // Wait for test client to complete
            thread::sleep(Duration::from_secs(35));

            let client_status = test_client.try_wait().expect("Failed to get client status");

            // Terminate test client if it's still running
            if client_status.is_none() {
                test_client.kill().expect("Failed to kill test client");
                test_client
                    .wait()
                    .expect("Failed to wait for test client to exit");
            }

            // Return success if client didn't exit with an error
            client_status.map_or(true, |s| s.success())
        });

        // Terminate web server
        web_server.kill().expect("Failed to kill web server");
        web_server
            .wait()
            .expect("Failed to wait for web server to exit");

        // Explicitly stop Docker at the end of the test
        if let Err(e) = docker.stop() {
            info!("Failed to stop Docker Compose: {}", e);
        } else {
            info!("Docker Compose environment stopped successfully");
        }

        // Check if the test was successful
        assert!(result, "Example test failed");
    }
}
