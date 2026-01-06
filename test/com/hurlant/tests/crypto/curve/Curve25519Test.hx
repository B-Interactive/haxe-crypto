package com.hurlant.tests.crypto.curve;

import com.hurlant.tests.*;
import com.hurlant.crypto.cert.curve.Curve25519;
import com.hurlant.util.Hex;
import haxe.io.Bytes;

class Curve25519Test extends BaseTestCase {
	/**
	 * Test basic key generation and shared secret computation
	 */
	public function test_basic_key_exchange() {
		// Generate two key pairs
		var alicePrivateKey = Bytes.alloc(32);
		var bobPrivateKey = Bytes.alloc(32);

		// Use secure random data for testing (in real code, use SecureRandom)
		alicePrivateKey.set(0, 1);
		alicePrivateKey.set(1, 2);
		alicePrivateKey.set(2, 3);
		bobPrivateKey.set(0, 4);
		bobPrivateKey.set(1, 5);
		bobPrivateKey.set(2, 6);

		// Generate public keys
		var alicePublicKey = Curve25519.genKeypair(alicePrivateKey);
		var bobPublicKey = Curve25519.genKeypair(bobPrivateKey);

		// Compute shared secrets
		var aliceShared = Curve25519.combineKeys(alicePrivateKey, bobPublicKey);
		var bobShared = Curve25519.combineKeys(bobPrivateKey, alicePublicKey);

		// Shared secrets should be equal
		assertBytesEqual("Shared secrets should match", aliceShared, bobShared);
	}

	/**
	 * Test with known test vectors from RFC 7748
	 */
	public function test_known_vectors() {
		// Test vector from RFC 7748
		var privateKeyHex = "77076d0a7318a57d3c16c17251b2664560a02102240087f9907915e75142179300000000";
		var publicKeyHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4e2ce32a378c000000000";
		var sharedSecretHex = "4a5d9d5ba4ce2de1728e3b60e67f0a83209a1732d2449b4a32c703059775278400000000";

		var privateKeyBytes = Hex.toBytes(privateKeyHex);
		var publicKeyBytes = Hex.toBytes(publicKeyHex);
		var expectedSharedBytes = Hex.toBytes(sharedSecretHex);

		// Generate public key
		var actualPublicKey = Curve25519.genKeypair(privateKeyBytes);

		// Compute shared secret
		var actualShared = Curve25519.combineKeys(privateKeyBytes, publicKeyBytes);

		// Verify results match expected values
		assertBytesEqual("Public key should match", actualPublicKey, publicKeyBytes);
		assertBytesEqual("Shared secret should match", actualShared, expectedSharedBytes);
	}

	/**
	 * Test key generation with all zeros (should be valid)
	 */
	public function test_zero_private_key() {
		var zeroKey = Bytes.alloc(32);
		for (i in 0...32) {
			zeroKey.set(i, 0);
		}

		// Should not throw exception
		var publicKey = Curve25519.genKeypair(zeroKey);
		assert(publicKey != null, "Public key should be generated");
	}

	/**
	 * Test that invalid key lengths throw exceptions
	 */
	public function test_invalid_key_lengths() {
		try {
			var shortKey = Bytes.alloc(31); // Too short
			Curve25519.genKeypair(shortKey);
			assert(false, "Should have thrown exception for short private key");
		} catch (e:Dynamic) {
			// Exception was thrown as expected
		}

		try {
			var shortKey = Bytes.alloc(31); // Too short
			Curve25519.combineKeys(shortKey, Bytes.alloc(32));
			assert(false, "Should have thrown exception for short private key");
		} catch (e:Dynamic) {
			// Exception was thrown as expected
		}

		try {
			var shortKey = Bytes.alloc(32);
			Curve25519.combineKeys(shortKey, Bytes.alloc(31)); // Too short
			assert(false, "Should have thrown exception for short public key");
		} catch (e:Dynamic) {
			// Exception was thrown as expected
		}
	}

	/**
	 * Test that the same private key produces consistent results
	 */
	public function test_consistent_results() {
		var privateKey = Bytes.alloc(32);
		privateKey.set(0, 123);
		privateKey.set(1, 45);
		privateKey.set(2, 67);

		// Generate public keys multiple times
		var publicKey1 = Curve25519.genKeypair(privateKey);
		var publicKey2 = Curve25519.genKeypair(privateKey);

		assertBytesEqual("Public key should be consistent", publicKey1, publicKey2);
	}

	/**
	 * Test with different inputs to ensure no side effects
	 */
	public function test_different_inputs() {
		var key1 = Bytes.alloc(32);
		var key2 = Bytes.alloc(32);

		// Fill with different values
		for (i in 0...32) {
			key1.set(i, i);
			key2.set(i, i + 1);
		}

		var pub1 = Curve25519.genKeypair(key1);
		var pub2 = Curve25519.genKeypair(key2);

		// Different private keys should produce different public keys
		if (bytesEqual(pub1, pub2)) {
			assert(false, "Public keys should be different");
		}
	}

	/**
	 * Helper to compare two bytes arrays for equality
	 */
	private function assertBytesEqual(message:String, a:Bytes, b:Bytes):Void {
		if (a.length != b.length) {
			assert(false, message + " - Lengths differ");
			return;
		}

		for (i in 0...a.length) {
			if (a.get(i) != b.get(i)) {
				assert(false, message + " - Bytes at index " + i + " differ");
				return;
			}
		}
	}

	/**
	 * Helper to compare two bytes arrays for equality
	 */
	private function bytesEqual(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length)
			return false;
		for (i in 0...a.length) {
			if (a.get(i) != b.get(i))
				return false;
		}
		return true;
	}
}
