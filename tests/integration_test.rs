#[cfg(test)]
mod integration_tests {
    use std::path::Path;
    
    #[test]
    fn test_workspace_structure() {
        // Test that all main crate directories exist
        assert!(Path::new("client").exists(), "Client crate directory should exist");
        assert!(Path::new("host").exists(), "Host crate directory should exist");
        assert!(Path::new("enclave").exists(), "Enclave crate directory should exist");
        
        // Test that all Cargo.toml files exist
        assert!(Path::new("Cargo.toml").exists(), "Workspace Cargo.toml should exist");
        assert!(Path::new("client/Cargo.toml").exists(), "Client Cargo.toml should exist");
        assert!(Path::new("host/Cargo.toml").exists(), "Host Cargo.toml should exist");
        assert!(Path::new("enclave/Cargo.toml").exists(), "Enclave Cargo.toml should exist");
    }
    
    #[test]
    fn test_mock_feature_compilation() {
        // This test ensures that the mock features compile correctly
        // The actual compilation is tested by the build system
        assert!(cfg!(feature = "mock"), "Mock feature should be enabled by default");
    }
}