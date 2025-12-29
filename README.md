# EphemeralML Zero-Trust AI Inference

A zero-trust AI inference system that protects intellectual property by separating neural network weights from topology information, using AWS Nitro Enclaves for secure execution.

## Architecture

The system consists of three main components:

- **Client**: Handles model decomposition and secure communication
- **Host**: Acts as an unprivileged proxy for weight storage and communication
- **Enclave**: Provides isolated execution environment for ephemeral model assembly and inference

## Development Modes

### Mock Mode (Default)

For local development and testing without AWS infrastructure:

- Uses TCP communication instead of VSock
- Provides mock attestation documents
- Simulates enclave isolation locally
- Enables rapid development and testing

### Production Mode

For deployment on AWS Nitro Enclaves:

- Uses VSock for host-enclave communication
- Generates real attestation documents using NSM API
- Provides hardware-based isolation guarantees

## Getting Started

### Prerequisites

- Rust 1.70+ with Cargo
- For production mode: AWS EC2 instance with Nitro Enclaves support

### Building

```bash
# Build all components in mock mode (default)
cargo build

# Build for production mode
cargo build --features production --no-default-features
```

### Running Mock Mode

1. **Start the mock enclave server:**
   ```bash
   cd enclave
   cargo run
   ```

2. **Start the host proxy (in another terminal):**
   ```bash
   cd host
   cargo run
   ```

3. **Run the client (in another terminal):**
   ```bash
   cd client
   cargo run
   ```

### Testing

```bash
# Run all tests
cargo test

# Run tests with mock features
cargo test --features mock

# Run property-based tests
cargo test --features mock -- --test-threads=1
```

## Project Structure

```
├── client/          # Client-side model decomposition and secure communication
├── host/            # Host proxy for weight storage and communication forwarding
├── enclave/         # Enclave-based ephemeral assembly and inference execution
├── Cargo.toml       # Workspace configuration
└── README.md        # This file
```

## Features

- **Mock Mode**: `mock` (default) - Local development with TCP communication
- **Production Mode**: `production` - AWS Nitro Enclaves with VSock and real attestation

## Security Model

1. **Model Decomposition**: Neural networks are split into unstructured weights (stored on host) and topology keys (held by client)
2. **Ephemeral Assembly**: Functional models exist only during inference execution (milliseconds)
3. **Hardware Isolation**: AWS Nitro Enclaves provide hardware-based isolation and attestation
4. **Zero-Trust Communication**: All communication is encrypted and authenticated

## Development Status

This is the initial workspace setup with mock mode support. Core functionality will be implemented in subsequent tasks according to the implementation plan in `.kiro/specs/ephemeral-inference/tasks.md`.

## License

This project is part of the EphemeralML research initiative.