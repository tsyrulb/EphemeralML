# Requirements Document

## Introduction

EphemeralML is a zero-trust AI inference system that protects intellectual property and sensitive data by separating neural network weights from topology information. The system uses AWS Nitro Enclaves to create an isolated execution environment where models are dynamically assembled only during inference, preventing reverse engineering and data theft.

## Glossary

- **Client**: The trusted entity that owns both the data and model architecture
- **Host**: The untrusted EC2 instance that acts as a gateway proxy
- **Enclave**: The AWS Nitro Enclave providing isolated, attested execution environment
- **Topology_Key**: The computation graph structure that defines neural network connections
- **Unstructured_Weights**: The floating-point weight values stored separately from topology
- **Ephemeral_Assembly**: The process of dynamically constructing a functional model from weights and topology
- **VSock**: Virtual socket communication channel between host and enclave
- **PCR_Hash**: Platform Configuration Register hash used for attestation

## Requirements

### Requirement 1: Secure Model Decomposition

**User Story:** As a model owner, I want to separate my neural network into unstructured weights and topology keys, so that neither component alone reveals my intellectual property.

#### Acceptance Criteria

1. WHEN a neural network model is processed, THE System SHALL extract weight matrices into unstructured floating-point arrays
2. WHEN topology extraction occurs, THE System SHALL serialize the computation graph structure separately from weights
3. THE System SHALL ensure that unstructured weights contain no architectural information
4. WHEN weights are stored on the server, THE System SHALL verify they cannot be reverse-engineered without the topology key
5. THE System SHALL support ONNX format models for decomposition using operators compatible with the Candle framework
6. WHEN validating ONNX models, THE System SHALL verify all operators are supported by the current Candle version

### Requirement 2: Secure Client Communication

**User Story:** As a client, I want to establish an authenticated and encrypted channel with the enclave, so that my data and topology keys are protected during transmission.

#### Acceptance Criteria

1. WHEN establishing communication, THE Client SHALL verify the enclave's attestation using PCR hash validation
2. WHEN sending data, THE Client SHALL encrypt input data using AWS KMS keys bound to the enclave's identity
3. WHEN transmitting topology keys, THE Client SHALL use the attested secure channel
4. IF attestation fails, THEN THE Client SHALL refuse to send sensitive data
5. THE Client SHALL validate the enclave's code integrity before each inference session

### Requirement 3: Ephemeral Model Assembly

**User Story:** As an enclave process, I want to dynamically assemble neural networks from topology keys and weights, so that functional models exist only during inference execution.

#### Acceptance Criteria

1. WHEN receiving a topology key, THE Enclave SHALL dynamically construct the computation graph in memory
2. WHEN weights are loaded, THE Enclave SHALL map them to the appropriate graph nodes according to the topology
3. WHEN inference completes, THE Enclave SHALL immediately destroy the assembled model structure from memory
4. THE Enclave SHALL ensure no persistent storage of assembled models
5. WHEN memory is cleared, THE Enclave SHALL overwrite memory locations containing model structure

### Requirement 4: Secure Inference Execution

**User Story:** As a system operator, I want inference to execute within the isolated enclave environment, so that neither the host nor cloud provider can access the functional model or data.

#### Acceptance Criteria

1. WHEN performing inference, THE Enclave SHALL execute computations using the Candle ML framework
2. WHEN processing input data, THE Enclave SHALL decrypt data only within the isolated environment
3. THE Enclave SHALL complete inference operations without exposing intermediate results to the host
4. WHEN inference finishes, THE Enclave SHALL return only the encrypted result to the client
5. THE Enclave SHALL log no sensitive information that could reveal model structure or data

### Requirement 5: Host Gateway Functionality

**User Story:** As a system architect, I want the host to act as an unprivileged proxy, so that it cannot access sensitive data while still facilitating communication.

#### Acceptance Criteria

1. THE Host SHALL forward encrypted payloads between client and enclave via VSock
2. THE Host SHALL have no capability to decrypt client data or topology keys
3. WHEN receiving client requests, THE Host SHALL relay them without inspection or modification
4. THE Host SHALL maintain no persistent storage of client communications
5. IF the host is compromised, THEN it SHALL contain no functional model or sensitive data

### Requirement 6: Memory Security and Anti-Forensics

**User Story:** As a security engineer, I want to ensure that memory dumps cannot reveal model structure, so that physical attacks yield no useful information.

#### Acceptance Criteria

1. WHEN model assembly occurs, THE System SHALL use volatile memory that cannot be persisted
2. WHEN clearing memory, THE System SHALL overwrite all locations containing model topology
3. THE System SHALL ensure weight-to-topology mappings exist only during active inference
4. WHEN inference completes, THE System SHALL verify no model artifacts remain in memory
5. IF memory is dumped during inference, THEN the exposure window SHALL be limited to milliseconds

### Requirement 7: Performance and Scalability

**User Story:** As a system user, I want inference performance to be near-native speed, so that security measures don't significantly impact usability.

#### Acceptance Criteria

1. THE System SHALL achieve inference performance within 15% of native execution speed
2. WHEN handling concurrent requests, THE System SHALL maintain performance characteristics
3. THE System SHALL support multiple model architectures without performance degradation
4. WHEN scaling inference requests, THE System SHALL handle load efficiently within enclave constraints
5. THE System SHALL minimize memory allocation overhead during ephemeral assembly

### Requirement 8: Error Handling and Resilience

**User Story:** As a system administrator, I want robust error handling for security and operational failures, so that the system fails securely and provides appropriate diagnostics.

#### Acceptance Criteria

1. IF attestation fails, THEN THE System SHALL terminate the session and log the security event
2. WHEN memory allocation fails, THE System SHALL clean up partial model structures before failing
3. IF topology key validation fails, THEN THE System SHALL reject the inference request
4. WHEN communication errors occur, THE System SHALL maintain security boundaries during error recovery
5. THE System SHALL provide diagnostic information without exposing sensitive details

### Requirement 9: Audit and Compliance

**User Story:** As a compliance officer, I want comprehensive audit trails for security events, so that I can verify system security and investigate incidents.

#### Acceptance Criteria

1. THE System SHALL log all attestation events with timestamps and outcomes
2. WHEN security violations occur, THE System SHALL generate immutable audit records
3. THE System SHALL track inference session lifecycles without logging sensitive data
4. WHEN model assembly occurs, THE System SHALL record assembly and destruction events
5. THE System SHALL provide audit reports for compliance verification