#[cfg(test)]
mod tests {
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
    #[ignore] // This test requires docker-compose vaults to be running
    fn test_example_web_server() {
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
            let mut test_client = start_process("cargo", &["run", "--example", "test_client"]);

            // Wait for test client to complete
            thread::sleep(Duration::from_secs(35));

            let client_status = test_client.try_wait().expect("Failed to get client status");

            // Terminate test client if it's still running
            if client_status.is_none() {
                test_client.kill().expect("Failed to kill test client");
            }

            // Return success if client didn't exit with an error
            client_status.map_or(true, |s| s.success())
        });

        // Terminate web server
        web_server.kill().expect("Failed to kill web server");

        // Check if the test was successful
        assert!(result, "Example test failed");
    }
}
