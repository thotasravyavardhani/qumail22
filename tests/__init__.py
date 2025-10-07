#!/usr/bin/env python3
"""
QuMail Tests

Test suite for QuMail application
"""

import unittest
import asyncio
from ..crypto.cipher_strategies import CipherManager
from ..crypto.kme_simulator import KMESimulator

class TestCipherStrategies(unittest.TestCase):
    """Test cipher strategies"""
    
    def setUp(self):
        self.cipher_manager = CipherManager()
        
    def test_quantum_aes_encryption(self):
        """Test Q-AES encryption/decryption"""
        test_data = b"Hello, Quantum World!"
        test_key = b"quantum_key_material_32_bytes_long"
        
        # Encrypt
        encrypted = self.cipher_manager.encrypt_with_level(test_data, test_key, 'L2')
        
        # Decrypt
        decrypted = self.cipher_manager.decrypt_with_level(encrypted, test_key)
        
        self.assertEqual(test_data, decrypted)
        
    def test_otp_encryption(self):
        """Test OTP encryption/decryption"""
        test_data = b"Secret message"
        test_key = b"x" * len(test_data)  # Key same length as data
        
        # Encrypt
        encrypted = self.cipher_manager.encrypt_with_level(test_data, test_key, 'L1')
        
        # Decrypt
        decrypted = self.cipher_manager.decrypt_with_level(encrypted, test_key)
        
        self.assertEqual(test_data, decrypted)
        
class TestKMESimulator(unittest.TestCase):
    """Test KME simulator"""
    
    def setUp(self):
        self.kme = KMESimulator()
        
    def test_key_generation(self):
        """Test quantum key generation"""
        key = self.kme._generate_quantum_key(
            sender_sae_id="alice",
            receiver_sae_id="bob",
            length_bits=256,
            key_type="seed"
        )
        
        self.assertEqual(len(key.key_data), 32)  # 256 bits = 32 bytes
        self.assertEqual(key.length, 256)
        self.assertEqual(key.sender_sae_id, "alice")
        self.assertEqual(key.receiver_sae_id, "bob")
        
if __name__ == '__main__':
    unittest.main()
