// Re-export common error types with enclave-specific extensions
pub use ephemeral_ml_common::{EphemeralError, EnclaveError, EnclaveResult};

// Enclave-specific result type alias for convenience
pub type Result<T> = EnclaveResult<T>;