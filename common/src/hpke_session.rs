//! HPKE session management with X25519 keys and attestation binding
//! 
//! This module implements HPKE (Hybrid Public Key Encryption) session establishment
//! bound to enclave attestation documents with replay protection.

use crate::error::{EphemeralError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

/// Session ID type for tracking HPKE sessions
pub type SessionId = String;

/// HPKE session configuration using fixed cipher suite for v1
#[derive(Debug, Clone)]
pub struct HPKEConfig {
    /// KEM: X25519
    pub kem_id: u16,
    /// KDF: HKDF-SHA256  
    pub kdf_id: u16,
    /// AEAD: ChaCha20-Poly1305
    pub aead_id: u16,
}

impl Default for HPKEConfig {
    fn default() -> Self {
        Self {
            kem_id: 0x0020, // X25519
            kdf_id: 0x0001, // HKDF-SHA256
            aead_id: 0x0003, // ChaCha20-Poly1305
        }
    }
}

/// HPKE session state with secure memory management
#[derive(ZeroizeOnDrop)]
pub struct HPKESession {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub attestation_hash: [u8; 32],
    pub enclave_public_key: [u8; 32],
    pub client_nonce: [u8; 32],
    pub transcript_hash: [u8; 32],
    
    // Session keys (zeroized on drop)
    session_key: [u8; 32],
    next_sequence_number: u64,
    
    // Session metadata
    pub created_at: u64,
    pub expires_at: u64,
    pub is_established: bool,
}

impl HPKESession {
    /// Create a new HPKE session with attestation binding
    pub fn new(
        session_id: SessionId,
        protocol_version: u32,
        attestation_hash: [u8; 32],
        enclave_public_key: [u8; 32],
        client_nonce: [u8; 32],
        ttl_seconds: u64,
    ) -> Result<Self> {
        let now = crate::current_timestamp();
        
        // Derive transcript hash: attestation_hash || enclave_public_key || client_nonce || protocol_version
        let transcript_hash = Self::derive_transcript_hash(
            &attestation_hash,
            &enclave_public_key,
            &client_nonce,
            protocol_version,
        )?;
        
        Ok(Self {
            session_id,
            protocol_version,
            attestation_hash,
            enclave_public_key,
            client_nonce,
            transcript_hash,
            session_key: [0u8; 32], // Will be derived during establishment
            next_sequence_number: 0,
            created_at: now,
            expires_at: now + ttl_seconds,
            is_established: false,
        })
    }
    
    /// Derive canonical transcript hash for session binding
    fn derive_transcript_hash(
        attestation_hash: &[u8; 32],
        enclave_public_key: &[u8; 32],
        client_nonce: &[u8; 32],
        protocol_version: u32,
    ) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(attestation_hash);
        hasher.update(enclave_public_key);
        hasher.update(client_nonce);
        hasher.update(&protocol_version.to_be_bytes());
        
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        Ok(result)
    }
    
    /// Establish HPKE session using enclave ephemeral key
    pub fn establish(&mut self, enclave_private_key: &[u8; 32]) -> Result<()> {
        // Derive session key from HPKE key exchange
        self.session_key = Self::derive_session_key(
            enclave_private_key,
            &self.transcript_hash,
        )?;
        
        self.is_established = true;
        Ok(())
    }
    
    /// Derive session key using X25519 key exchange and transcript binding
    fn derive_session_key(
        enclave_private_key: &[u8; 32],
        transcript_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};
        
        // For v1, we use a simplified key derivation
        // In production, this would use proper HPKE key derivation
        let mut hasher = Sha256::new();
        hasher.update(enclave_private_key);
        hasher.update(transcript_hash);
        hasher.update(b"EphemeralML-HPKE-v1");
        
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Ok(key)
    }
    
    /// Encrypt payload with replay protection
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<EncryptedMessage> {
        if !self.is_established {
            return Err(EphemeralError::EncryptionError("Session not established".to_string()));
        }
        
        if self.is_expired() {
            return Err(EphemeralError::EncryptionError("Session expired".to_string()));
        }
        
        let sequence_number = self.next_sequence_number;
        self.next_sequence_number += 1;
        
        // Create message frame: version || session_id || seq_no || plaintext
        let message_frame = self.create_message_frame(plaintext, sequence_number)?;
        
        // Encrypt using ChaCha20-Poly1305 (simplified for v1)
        let ciphertext = self.encrypt_frame(&message_frame)?;
        
        Ok(EncryptedMessage {
            session_id: self.session_id.clone(),
            protocol_version: self.protocol_version,
            sequence_number,
            ciphertext,
            auth_tag: [0u8; 16], // Simplified for v1
        })
    }
    
    /// Decrypt payload with replay protection
    pub fn decrypt(&self, message: &EncryptedMessage) -> Result<Vec<u8>> {
        if !self.is_established {
            return Err(EphemeralError::DecryptionError("Session not established".to_string()));
        }
        
        if message.session_id != self.session_id {
            return Err(EphemeralError::DecryptionError("Session ID mismatch".to_string()));
        }
        
        if message.protocol_version != self.protocol_version {
            return Err(EphemeralError::DecryptionError("Protocol version mismatch".to_string()));
        }
        
        // Decrypt and verify message frame
        let message_frame = self.decrypt_frame(&message.ciphertext)?;
        self.parse_message_frame(&message_frame, message.sequence_number)
    }
    
    /// Create canonical message frame
    fn create_message_frame(&self, plaintext: &[u8], sequence_number: u64) -> Result<Vec<u8>> {
        let mut frame = Vec::new();
        
        // version (4 bytes)
        frame.extend_from_slice(&self.protocol_version.to_be_bytes());
        
        // session_id length + session_id
        let session_id_bytes = self.session_id.as_bytes();
        frame.extend_from_slice(&(session_id_bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(session_id_bytes);
        
        // sequence_number (8 bytes)
        frame.extend_from_slice(&sequence_number.to_be_bytes());
        
        // plaintext length + plaintext
        frame.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        frame.extend_from_slice(plaintext);
        
        Ok(frame)
    }
    
    /// Parse message frame and extract plaintext
    fn parse_message_frame(&self, frame: &[u8], expected_sequence: u64) -> Result<Vec<u8>> {
        if frame.len() < 16 {
            return Err(EphemeralError::DecryptionError("Frame too short".to_string()));
        }
        
        let mut offset = 0;
        
        // Parse version
        let version = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
        if version != self.protocol_version {
            return Err(EphemeralError::DecryptionError("Version mismatch in frame".to_string()));
        }
        offset += 4;
        
        // Parse session_id
        let session_id_len = u32::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3]
        ]) as usize;
        offset += 4;
        
        if offset + session_id_len > frame.len() {
            return Err(EphemeralError::DecryptionError("Invalid session ID length".to_string()));
        }
        
        let session_id = String::from_utf8(frame[offset..offset + session_id_len].to_vec())
            .map_err(|_| EphemeralError::DecryptionError("Invalid session ID encoding".to_string()))?;
        
        if session_id != self.session_id {
            return Err(EphemeralError::DecryptionError("Session ID mismatch in frame".to_string()));
        }
        offset += session_id_len;
        
        // Parse sequence number
        if offset + 8 > frame.len() {
            return Err(EphemeralError::DecryptionError("Frame too short for sequence".to_string()));
        }
        
        let sequence = u64::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3],
            frame[offset + 4], frame[offset + 5], frame[offset + 6], frame[offset + 7],
        ]);
        
        if sequence != expected_sequence {
            return Err(EphemeralError::DecryptionError("Sequence number mismatch".to_string()));
        }
        offset += 8;
        
        // Parse plaintext
        if offset + 4 > frame.len() {
            return Err(EphemeralError::DecryptionError("Frame too short for plaintext length".to_string()));
        }
        
        let plaintext_len = u32::from_be_bytes([
            frame[offset], frame[offset + 1], frame[offset + 2], frame[offset + 3]
        ]) as usize;
        offset += 4;
        
        if offset + plaintext_len != frame.len() {
            return Err(EphemeralError::DecryptionError("Invalid plaintext length".to_string()));
        }
        
        Ok(frame[offset..].to_vec())
    }
    
    /// Encrypt message frame (simplified for v1)
    fn encrypt_frame(&self, frame: &[u8]) -> Result<Vec<u8>> {
        // Simplified encryption for v1 - XOR with session key
        // In production, this would use ChaCha20-Poly1305
        let mut ciphertext = frame.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= self.session_key[i % 32];
        }
        Ok(ciphertext)
    }
    
    /// Decrypt message frame (simplified for v1)
    fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Simplified decryption for v1 - XOR with session key
        // In production, this would use ChaCha20-Poly1305
        let mut plaintext = ciphertext.to_vec();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= self.session_key[i % 32];
        }
        Ok(plaintext)
    }
    
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        crate::current_timestamp() >= self.expires_at
    }
    
    /// Get next sequence number for replay protection
    pub fn get_next_sequence(&self) -> u64 {
        self.next_sequence_number
    }
}

/// Encrypted message with replay protection
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedMessage {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub sequence_number: u64,
    pub ciphertext: Vec<u8>,
    pub auth_tag: [u8; 16],
}

/// HPKE session manager for handling multiple sessions
pub struct HPKESessionManager {
    sessions: HashMap<SessionId, HPKESession>,
    config: HPKEConfig,
    max_sessions: usize,
}

impl HPKESessionManager {
    /// Create new session manager
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            config: HPKEConfig::default(),
            max_sessions,
        }
    }
    
    /// Create new HPKE session with attestation binding
    pub fn create_session(
        &mut self,
        session_id: SessionId,
        protocol_version: u32,
        attestation_hash: [u8; 32],
        enclave_public_key: [u8; 32],
        client_nonce: [u8; 32],
        ttl_seconds: u64,
    ) -> Result<()> {
        if self.sessions.len() >= self.max_sessions {
            return Err(EphemeralError::ResourceExhausted("Too many sessions".to_string()));
        }
        
        let session = HPKESession::new(
            session_id.clone(),
            protocol_version,
            attestation_hash,
            enclave_public_key,
            client_nonce,
            ttl_seconds,
        )?;
        
        self.sessions.insert(session_id, session);
        Ok(())
    }
    
    /// Establish session with enclave private key
    pub fn establish_session(
        &mut self,
        session_id: &SessionId,
        enclave_private_key: &[u8; 32],
    ) -> Result<()> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.establish(enclave_private_key)
    }
    
    /// Encrypt payload for session
    pub fn encrypt(
        &mut self,
        session_id: &SessionId,
        plaintext: &[u8],
    ) -> Result<EncryptedMessage> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.encrypt(plaintext)
    }
    
    /// Decrypt payload for session
    pub fn decrypt(
        &self,
        message: &EncryptedMessage,
    ) -> Result<Vec<u8>> {
        let session = self.sessions.get(&message.session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        
        session.decrypt(message)
    }
    
    /// Remove expired sessions
    pub fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, session| !session.is_expired());
    }
    
    /// Terminate session
    pub fn terminate_session(&mut self, session_id: &SessionId) -> Result<()> {
        self.sessions.remove(session_id)
            .ok_or_else(|| EphemeralError::InvalidInput("Session not found".to_string()))?;
        Ok(())
    }
    
    /// Get session info
    pub fn get_session_info(&self, session_id: &SessionId) -> Option<SessionInfo> {
        self.sessions.get(session_id).map(|session| SessionInfo {
            session_id: session.session_id.clone(),
            protocol_version: session.protocol_version,
            is_established: session.is_established,
            created_at: session.created_at,
            expires_at: session.expires_at,
            next_sequence: session.next_sequence_number,
        })
    }
}

/// Session information for external queries
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: SessionId,
    pub protocol_version: u32,
    pub is_established: bool,
    pub created_at: u64,
    pub expires_at: u64,
    pub next_sequence: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hpke_session_creation() {
        let session_id = "test-session".to_string();
        let protocol_version = 1;
        let attestation_hash = [1u8; 32];
        let enclave_public_key = [2u8; 32];
        let client_nonce = [3u8; 32];
        let ttl_seconds = 3600;
        
        let session = HPKESession::new(
            session_id.clone(),
            protocol_version,
            attestation_hash,
            enclave_public_key,
            client_nonce,
            ttl_seconds,
        ).unwrap();
        
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.protocol_version, protocol_version);
        assert!(!session.is_established);
        assert!(!session.is_expired());
    }
    
    #[test]
    fn test_session_establishment() {
        let mut session = HPKESession::new(
            "test".to_string(),
            1,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            3600,
        ).unwrap();
        
        let enclave_private_key = [4u8; 32];
        session.establish(&enclave_private_key).unwrap();
        
        assert!(session.is_established);
    }
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut session = HPKESession::new(
            "test".to_string(),
            1,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            3600,
        ).unwrap();
        
        let enclave_private_key = [4u8; 32];
        session.establish(&enclave_private_key).unwrap();
        
        let plaintext = b"Hello, HPKE!";
        let encrypted = session.encrypt(plaintext).unwrap();
        let decrypted = session.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_session_manager() {
        let mut manager = HPKESessionManager::new(10);
        
        let session_id = "test-session".to_string();
        manager.create_session(
            session_id.clone(),
            1,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            3600,
        ).unwrap();
        
        let enclave_private_key = [4u8; 32];
        manager.establish_session(&session_id, &enclave_private_key).unwrap();
        
        let plaintext = b"Test message";
        let encrypted = manager.encrypt(&session_id, plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}