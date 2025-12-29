use crate::{HostError, Result, VSockProxy, WeightStorage, EphemeralError};
use std::collections::HashMap;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Helper function to convert std::io::Error to HostError
fn io_error_to_host_error(err: std::io::Error) -> HostError {
    HostError::Host(EphemeralError::IoError(err.to_string()))
}

/// Mock VSock proxy that uses TCP for local development
pub struct MockVSockProxy {
    pub tcp_port: u16,
    pub weight_storage: HashMap<String, Vec<f32>>,
}

impl MockVSockProxy {
    pub fn new(tcp_port: u16) -> Self {
        Self {
            tcp_port,
            weight_storage: HashMap::new(),
        }
    }

    /// Start a mock TCP server that simulates enclave communication
    pub async fn start_mock_server(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.tcp_port))
            .await
            .map_err(|e| HostError::Host(EphemeralError::ProxyError(format!("Failed to bind TCP listener: {}", e))))?;

        println!("Mock VSock proxy listening on TCP port {}", self.tcp_port);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    println!("Mock connection from {}", addr);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_mock_connection(stream).await {
                            eprintln!("Error handling mock connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    async fn handle_mock_connection(mut stream: TcpStream) -> Result<()> {
        let mut buffer = vec![0u8; 4096];
        let bytes_read = stream.read(&mut buffer).await.map_err(io_error_to_host_error)?;
        
        if bytes_read == 0 {
            return Ok(());
        }

        // Echo back the data with a mock response prefix
        let response = format!("MOCK_RESPONSE:{}", String::from_utf8_lossy(&buffer[..bytes_read]));
        stream.write_all(response.as_bytes()).await.map_err(io_error_to_host_error)?;
        stream.flush().await.map_err(io_error_to_host_error)?;
        
        Ok(())
    }
}

impl VSockProxy for MockVSockProxy {
    async fn forward_to_enclave(&self, payload: &[u8]) -> Result<Vec<u8>> {
        // Mock TCP communication instead of VSock
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", self.tcp_port))
            .await
            .map_err(|e| HostError::Host(EphemeralError::VSockError(format!("Failed to connect to mock enclave: {}", e))))?;

        // Send payload
        stream.write_all(payload).await.map_err(io_error_to_host_error)?;
        stream.flush().await.map_err(io_error_to_host_error)?;

        // Read response
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.map_err(io_error_to_host_error)?;

        Ok(response)
    }

    fn store_weights(&mut self, model_id: &str, weights: &[f32]) -> Result<()> {
        self.weight_storage.insert(model_id.to_string(), weights.to_vec());
        println!("Mock: Stored {} weights for model {}", weights.len(), model_id);
        Ok(())
    }

    fn retrieve_weights(&self, model_id: &str) -> Result<Vec<f32>> {
        self.weight_storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }
}

/// Mock weight storage for testing
pub struct MockWeightStorage {
    storage: HashMap<String, Vec<f32>>,
}

impl MockWeightStorage {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }
}

impl Default for MockWeightStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl WeightStorage for MockWeightStorage {
    fn store(&mut self, model_id: &str, weights: &[f32]) -> Result<()> {
        self.storage.insert(model_id.to_string(), weights.to_vec());
        println!("Mock storage: Stored {} weights for model {}", weights.len(), model_id);
        Ok(())
    }

    fn retrieve(&self, model_id: &str) -> Result<Vec<f32>> {
        self.storage
            .get(model_id)
            .cloned()
            .ok_or_else(|| HostError::Host(EphemeralError::StorageError(format!("Weights not found for model {}", model_id))))
    }

    fn exists(&self, model_id: &str) -> bool {
        self.storage.contains_key(model_id)
    }

    fn remove(&mut self, model_id: &str) -> Result<()> {
        self.storage.remove(model_id);
        println!("Mock storage: Removed weights for model {}", model_id);
        Ok(())
    }
}