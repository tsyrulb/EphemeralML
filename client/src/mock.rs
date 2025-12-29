use crate::{
    ClientError, Result, SecureChannel, EncryptedPayload, TopologyKey, AttestationDocument,
    PcrMeasurements, ModelDecomposer, SecureClient, WeightArrays, ModelMetadata, GraphNode,
    GraphEdge, TensorShape, OperationType, WeightIndex, WeightType, EphemeralError, PayloadType,
    current_timestamp, generate_nonce
};
use std::path::Path;
use uuid::Uuid;
use sha2::{Sha256, Digest};

/// Mock model decomposer for local development and testing
pub struct MockModelDecomposer;

impl ModelDecomposer for MockModelDecomposer {
    fn decompose_model(&self, onnx_path: &Path) -> Result<(TopologyKey, WeightArrays)> {
        // Create a mock topology key
        let topology = TopologyKey {
            graph_id: Uuid::new_v4().to_string(),
            nodes: vec![
                GraphNode {
                    node_id: "input".to_string(),
                    operation: OperationType::Linear,
                    parameters: std::collections::HashMap::new(),
                    weight_indices: vec![WeightIndex {
                        start_idx: 0,
                        length: 100,
                        shape: TensorShape { dimensions: vec![10, 10] },
                        weight_type: WeightType::Weights,
                    }],
                },
                GraphNode {
                    node_id: "output".to_string(),
                    operation: OperationType::Softmax,
                    parameters: std::collections::HashMap::new(),
                    weight_indices: vec![],
                },
            ],
            edges: vec![GraphEdge {
                from_node: "input".to_string(),
                to_node: "output".to_string(),
                tensor_shape: TensorShape { dimensions: vec![1, 10] },
            }],
            input_shapes: vec![TensorShape { dimensions: vec![1, 10] }],
            output_shapes: vec![TensorShape { dimensions: vec![1, 10] }],
            metadata: ModelMetadata {
                name: format!("mock_model_{}", onnx_path.file_name().unwrap_or_default().to_string_lossy()),
                version: "1.0.0".to_string(),
                description: Some("Mock model for testing".to_string()),
                created_at: current_timestamp(),
                checksum: "mock_checksum_hash".to_string(),
            },
        };

        // Create mock weight arrays using the constructor
        let weight_data = (0..100).map(|i| i as f32 * 0.01).collect();
        let weights = WeightArrays::new(topology.graph_id.clone(), weight_data);

        Ok((topology, weights))
    }

    fn validate_onnx_compatibility(&self, _model_path: &Path) -> Result<()> {
        // Mock validation always passes
        Ok(())
    }

    fn check_candle_operator_support(&self, operators: &[String]) -> Result<()> {
        // Mock check - reject operators containing "unsupported"
        for op in operators {
            if op.to_lowercase().contains("unsupported") {
                return Err(ClientError::Client(EphemeralError::UnsupportedOperatorError(format!("Operator {} not supported", op))));
            }
        }
        Ok(())
    }
}

/// Mock secure client for local development and testing
pub struct MockSecureClient {
    pub mock_attestation_valid: bool,
}

impl MockSecureClient {
    pub fn new() -> Self {
        Self {
            mock_attestation_valid: true,
        }
    }

    pub fn with_invalid_attestation() -> Self {
        Self {
            mock_attestation_valid: false,
        }
    }

    /// Generate a mock attestation document for testing
    pub fn generate_mock_attestation() -> AttestationDocument {
        let mut hasher = Sha256::new();
        hasher.update(b"mock_enclave_image");
        let digest_bytes = hasher.finalize();
        
        let mut digest = vec![0u8; 48];
        digest[..32].copy_from_slice(&digest_bytes);
        
        AttestationDocument {
            module_id: "mock-enclave".to_string(),
            digest,
            timestamp: current_timestamp(),
            pcrs: PcrMeasurements {
                pcr0: vec![0x01; 48], // Mock PCR0
                pcr1: vec![0x02; 48], // Mock PCR1
                pcr2: vec![0x03; 48], // Mock PCR2
            },
            certificate: b"mock_certificate".to_vec(),
            signature: b"mock_signature".to_vec(),
            nonce: Some(b"mock_nonce".to_vec()),
        }
    }
}

impl Default for MockSecureClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureClient for MockSecureClient {
    fn establish_attested_channel(&mut self, enclave_endpoint: &str) -> Result<SecureChannel> {
        if !self.mock_attestation_valid {
            return Err(ClientError::Client(EphemeralError::AttestationError("Mock attestation failed".to_string())));
        }

        let mut channel = SecureChannel::new(
            enclave_endpoint.to_string(),
            b"mock_session_key_32_bytes_long!!".to_vec(),
            3600, // 1 hour TTL
        );
        channel.mark_attestation_verified();
        Ok(channel)
    }

    fn encrypt_inference_request(&self, topology: &TopologyKey, data: &[f32]) -> Result<EncryptedPayload> {
        // Mock encryption - just serialize and "encrypt" with XOR
        let mut payload_data = Vec::new();
        let topology_bytes = serde_json::to_vec(topology)
            .map_err(|e| ClientError::Client(EphemeralError::SerializationError(e.to_string())))?;
        payload_data.extend_from_slice(&topology_bytes);
        payload_data.extend_from_slice(&data.iter().flat_map(|f| f.to_le_bytes()).collect::<Vec<u8>>());
        
        // Mock encryption with simple XOR
        let key = 0x42u8;
        let encrypted_data: Vec<u8> = payload_data.iter().map(|b| b ^ key).collect();
        
        Ok(EncryptedPayload {
            data: encrypted_data,
            nonce: generate_nonce(),
            key_id: "mock-kms-key".to_string(),
            payload_type: PayloadType::InferenceRequest,
        })
    }

    fn verify_enclave_attestation(&self, _attestation_doc: &[u8]) -> Result<bool> {
        Ok(self.mock_attestation_valid)
    }
}