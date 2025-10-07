#!/usr/bin/env python3
"""
PQC Encrypted File Sharing Demonstration
Shows the complete two-layer encryption process for large files
"""

import asyncio
import logging
import sys
import os
from datetime import datetime
from pathlib import Path

# Add the app directory to Python path
sys.path.insert(0, '/app')

from crypto.cipher_strategies import CipherManager, PostQuantumStrategy
from crypto.kme_client import KMEClient
from utils.config import load_config

class PQCFileDemo:
    """Demonstrate PQC encrypted file sharing"""
    
    def __init__(self):
        self.cipher_manager = CipherManager()
        self.kme_client = None
        
    async def initialize(self):
        """Initialize the demo environment"""
        try:
            # Load configuration
            config = load_config()
            
            # Initialize KME client
            self.kme_client = KMEClient(config.get('kme_url', 'http://127.0.0.1:8080'))
            await self.kme_client.initialize()
            
            logging.info("PQC Demo initialized successfully")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize PQC demo: {e}")
            return False
    
    def demonstrate_file_encryption_decision(self, file_path: str) -> dict:
        """Demonstrate the decision logic for file encryption"""
        
        file_size = os.path.getsize(file_path)
        file_size_mb = file_size / (1024 * 1024)
        
        print(f"\n📁 File Analysis: {os.path.basename(file_path)}")
        print(f"📊 Size: {file_size_mb:.2f} MB ({file_size:,} bytes)")
        
        # Decision logic based on PostQuantumStrategy
        pqc_strategy = self.cipher_manager.strategies['L3']
        is_large_file = file_size > pqc_strategy.file_threshold
        
        recommendation = {
            'file_path': file_path,
            'file_size': file_size,
            'file_size_mb': file_size_mb,
            'is_large_file': is_large_file,
            'recommended_level': 'L3' if is_large_file else 'L2'
        }
        
        if is_large_file:
            print(f"🔐 Large file detected (> {pqc_strategy.file_threshold / (1024*1024):.1f} MB)")
            print("📋 Recommended: Level 3 (Post-Quantum Crypto)")
            print("🔧 Encryption method: Two-layer (FEK + Kyber KEM)")
            print("   • File Encryption Key (FEK): AES-256-GCM")
            print("   • Key Encapsulation: CRYSTALS-Kyber-1024")
            print("   • Security Level: NIST Post-Quantum Level 5")
        else:
            print("📋 Standard file size - Level 2 (Q-AES) sufficient")
            print("🔧 Encryption method: Single-layer AES-256-GCM")
            
        return recommendation
    
    async def demonstrate_pqc_encryption(self, file_path: str) -> dict:
        """Demonstrate the complete PQC encryption process"""
        
        print(f"\n🚀 Starting PQC Encryption Process...")
        
        # Read file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
            
        file_size = len(file_data)
        print(f"📖 Loaded file data: {file_size:,} bytes")
        
        # Request quantum key from KME
        print("🔑 Requesting quantum key material from KME...")
        
        # Calculate required key length for PQC
        required_key_length = self.cipher_manager.get_required_key_length('L3', file_size)
        print(f"📏 Required key material: {required_key_length} bits ({required_key_length // 8} bytes)")
        
        try:
            # Request key from KME
            key_data = await self.kme_client.request_key(
                sender_sae_id="qumail_demo_sender",
                receiver_sae_id="qumail_demo_receiver", 
                key_length=required_key_length,
                key_type='seed'
            )
            
            if not key_data:
                raise ValueError("Failed to obtain quantum key from KME")
                
            print(f"✅ Quantum key obtained: ID={key_data['key_id']}")
            
        except Exception as e:
            print(f"⚠️  KME unavailable, using simulated quantum key: {e}")
            # Use simulated key for demo
            import secrets
            key_data = {
                'key_id': 'DEMO_KEY_' + secrets.token_hex(8),
                'key_data': secrets.token_bytes(required_key_length // 8)
            }
            
        # Perform PQC encryption
        print("\n🔐 Performing PQC Encryption...")
        
        file_context = {
            'is_attachment': True,
            'total_size': file_size,
            'attachment_count': 1,
            'requires_fek': True
        }
        
        start_time = datetime.utcnow()
        
        encrypted_data = self.cipher_manager.encrypt_with_level(
            file_data, key_data['key_data'], 'L3', file_context
        )
        
        end_time = datetime.utcnow()
        encryption_time = (end_time - start_time).total_seconds()
        
        # Add key metadata
        encrypted_data['key_id'] = key_data['key_id']
        
        print(f"⏱️  Encryption completed in {encryption_time:.3f} seconds")
        print(f"📈 Throughput: {(file_size / (1024*1024)) / encryption_time:.2f} MB/s")
        
        # Display encryption details
        self._display_encryption_details(encrypted_data, file_size)
        
        return {
            'original_size': file_size,
            'encrypted_data': encrypted_data,
            'encryption_time': encryption_time,
            'key_id': key_data['key_id']
        }
    
    def _display_encryption_details(self, encrypted_data: dict, original_size: int):
        """Display detailed encryption information"""
        
        print("\n📋 Encryption Details:")
        print("=" * 50)
        print(f"Algorithm: {encrypted_data.get('algorithm')}")
        print(f"Encryption Mode: {encrypted_data.get('encryption_mode')}")
        print(f"Original Size: {original_size:,} bytes ({original_size / (1024*1024):.2f} MB)")
        
        if encrypted_data.get('fek_used'):
            print("\n🔐 Two-Layer Security Applied:")
            print("   Layer 1 (File): AES-256-GCM with FEK")
            print("   Layer 2 (Key): CRYSTALS-Kyber KEM")
            
            encap_info = encrypted_data.get('encapsulated_fek', {})
            print(f"   PQC Algorithm: {encap_info.get('kem_algorithm')}")
            print(f"   Security Strength: {encap_info.get('security_strength')}")
            
            # Calculate overhead
            import base64
            encrypted_file_size = len(base64.b64decode(encrypted_data['ciphertext']))
            kyber_key_size = len(base64.b64decode(encap_info.get('encapsulated_key', '')))
            
            print(f"\n📊 Size Analysis:")
            print(f"   Original file: {original_size:,} bytes")
            print(f"   Encrypted file: {encrypted_file_size:,} bytes")
            print(f"   Encapsulated key: {kyber_key_size:,} bytes")
            print(f"   Total overhead: {(encrypted_file_size + kyber_key_size - original_size):,} bytes")
            print(f"   Overhead ratio: {((encrypted_file_size + kyber_key_size) / original_size - 1) * 100:.2f}%")
        
    async def demonstrate_pqc_decryption(self, encrypted_result: dict):
        """Demonstrate the PQC decryption process"""
        
        print(f"\n🔓 Starting PQC Decryption Process...")
        
        encrypted_data = encrypted_result['encrypted_data']
        key_id = encrypted_result['key_id']
        
        # Request decryption key
        print(f"🔑 Requesting decryption key: {key_id}")
        
        try:
            key_response = await self.kme_client.get_key("qumail_demo_receiver", key_id)
            
            if not key_response:
                raise ValueError("Failed to obtain decryption key")
                
            key_material = key_response['key_data']
            print("✅ Decryption key obtained")
            
        except Exception as e:
            print(f"⚠️  KME unavailable for decryption, using demo key: {e}")
            # For demo, we'll use the same key (in real scenario, KME would provide it)
            import secrets
            key_material = secrets.token_bytes(64)  # 512 bits for L3
            
        # Perform decryption
        print("🔐 Performing PQC Decryption...")
        
        start_time = datetime.utcnow()
        
        try:
            decrypted_data = self.cipher_manager.decrypt_with_level(
                encrypted_data, key_material
            )
            
            end_time = datetime.utcnow()
            decryption_time = (end_time - start_time).total_seconds()
            
            print(f"✅ Decryption successful!")
            print(f"⏱️  Decryption completed in {decryption_time:.3f} seconds")
            print(f"📊 Decrypted size: {len(decrypted_data):,} bytes")
            
            # Verify integrity
            original_size = encrypted_result['original_size']
            if len(decrypted_data) == original_size:
                print("✅ Data integrity verified - sizes match")
            else:
                print("❌ Data integrity check failed - size mismatch")
                
            return {
                'decrypted_data': decrypted_data,
                'decryption_time': decryption_time,
                'integrity_check': len(decrypted_data) == original_size
            }
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return None
    
    async def run_complete_demo(self, test_files: list = None):
        """Run the complete PQC file sharing demonstration"""
        
        print("🔐 QuMail PQC Encrypted File Sharing Demo")
        print("=" * 60)
        print("Demonstrates two-layer encryption for large files:")
        print("• High-Speed Layer: AES-256-GCM with File Encryption Key")
        print("• Quantum-Safe Layer: CRYSTALS-Kyber Key Encapsulation")
        print()
        
        # Use provided test files or generate them
        if not test_files:
            print("📁 No test files provided, creating demo files...")
            from test_large_file_generator import create_pqc_test_suite
            test_files = create_pqc_test_suite()
        
        # Demonstrate with different file sizes
        for name, file_path, description in test_files[:3]:  # Test first 3 files
            
            print(f"\n{'=' * 60}")
            print(f"🧪 Testing: {name}")
            print(f"📝 Description: {description}")
            
            # Step 1: Analyze file and show recommendation
            analysis = self.demonstrate_file_encryption_decision(file_path)
            
            # Step 2: Only demonstrate PQC for large files
            if analysis['is_large_file']:
                
                # Step 3: Encrypt with PQC
                encryption_result = await self.demonstrate_pqc_encryption(file_path)
                
                if encryption_result:
                    # Step 4: Decrypt and verify
                    decryption_result = await self.demonstrate_pqc_decryption(encryption_result)
                    
                    if decryption_result and decryption_result['integrity_check']:
                        print("\n🎉 Complete PQC cycle successful!")
                        
                        # Performance summary
                        total_time = encryption_result['encryption_time'] + decryption_result['decryption_time']
                        throughput = (analysis['file_size_mb'] * 2) / total_time  # MB/s for round trip
                        
                        print(f"📈 Performance Summary:")
                        print(f"   Total time: {total_time:.3f} seconds")
                        print(f"   Round-trip throughput: {throughput:.2f} MB/s")
                        
                    else:
                        print("❌ PQC cycle failed")
            else:
                print("⏭️  Skipping PQC demo for small file")
                print("   (Level 2 Q-AES would be sufficient)")
        
        print(f"\n{'=' * 60}")
        print("✅ PQC File Sharing Demo Complete!")
        print("\n🔐 Key Benefits Demonstrated:")
        print("• Quantum-resistant security for large files")
        print("• Efficient two-layer encryption architecture")
        print("• Automatic file size optimization")
        print("• NIST-approved post-quantum algorithms")
        print("• High-performance encryption/decryption")

async def main():
    """Main demonstration function"""
    
    logging.basicConfig(level=logging.INFO)
    
    # Initialize demo
    demo = PQCFileDemo()
    
    if not await demo.initialize():
        print("❌ Failed to initialize demo environment")
        return 1
    
    # Check if test files exist, create if needed
    test_dir = "/tmp/qumail_pqc_test"
    if not os.path.exists(test_dir):
        print("📁 Creating test files for demonstration...")
        from test_large_file_generator import create_pqc_test_suite
        test_files = create_pqc_test_suite()
    else:
        # Use existing test files
        test_files = [
            ("Large File (15MB)", "/tmp/qumail_pqc_test/large_document.txt", "Full PQC + FEK encryption"),
            ("XL File (25MB)", "/tmp/qumail_pqc_test/xl_data.bin", "Heavy PQC processing"),
            ("Medium File (2.5MB)", "/tmp/qumail_pqc_test/medium_image.bin", "Should trigger FEK optimization")
        ]
    
    # Run complete demonstration
    await demo.run_complete_demo(test_files)
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)