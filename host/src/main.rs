use ephemeral_ml_host::{mock::MockVSockProxy, VSockProxy};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralNet Host Proxy (Mock Mode)");
    
    // Create mock proxy
    let mut proxy = MockVSockProxy::new(8081);
    
    // Test weight storage
    let test_weights: Vec<f32> = (0..100).map(|i| i as f32 * 0.01).collect();
    proxy.store_weights("test_model", &test_weights)?;
    println!("Stored {} weights for test_model", test_weights.len());
    
    // Test weight retrieval
    let retrieved_weights = proxy.retrieve_weights("test_model")?;
    println!("Retrieved {} weights for test_model", retrieved_weights.len());
    
    // Test payload forwarding (this would normally connect to enclave)
    println!("Mock proxy demo completed");
    println!("To test full communication, start the enclave server first");
    
    Ok(())
}