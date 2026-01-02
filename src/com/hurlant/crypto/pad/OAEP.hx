package com.hurlant.crypto.pad;

import com.hurlant.util.Std2;
import haxe.Int32;
import com.hurlant.crypto.hash.SHA1;
import com.hurlant.crypto.prng.SecureRandom;
import com.hurlant.math.BigInteger;
import com.hurlant.util.ByteArray;
import com.hurlant.crypto.tls.TLSError;

class OAEP {
	private var hash:com.hurlant.crypto.hash.IHash;
	private var mgf1SeedLength:Int;

	public function new(hash:com.hurlant.crypto.hash.IHash = null) {
		this.hash = (hash != null) ? hash : new SHA1();
		mgf1SeedLength = this.hash.getHashSize();
	}

	public function pad(src:ByteArray, end:Int32, n:Int32, type:Int32 = 0x02):ByteArray {
		// Calculate message length properly
		var mLen = end - src.position;
		var maxLen = n - 2 * mgf1SeedLength - 2;
		
		trace("OAEP pad debug:");
		trace("  n (key size in bytes): " + n);
		trace("  mgf1SeedLength: " + mgf1SeedLength);
		trace("  maxLen (max message length): " + maxLen);
		trace("  mLen (message length): " + mLen);
		
		// Check for valid parameters
		if (maxLen <= 0) {
			throw new TLSError("OAEP::pad: Key size too small for OAEP padding", TLSError.decode_error);
		}
		
		if (mLen > maxLen) {
			throw new TLSError("OAEP::pad: Message too long", TLSError.decode_error);
		}

		var m = new ByteArray();
		src.readBytes(m, 0, mLen);
		src.position += mLen;

		// Use consistent empty label hash (empty string)
		var lHash = hash.hash(new ByteArray());
		
		var db = new ByteArray();
		db.writeBytes(lHash);
		
		// Padding with zeros (ps) - n - mLen - 2*mgf1SeedLength - 2 bytes
		var psLen = n - mLen - 2 * mgf1SeedLength - 2;
		trace("  psLen (padding length): " + psLen);
		
		for (i in 0...psLen) {
			db.writeByte(0);
		}
		
		db.writeByte(1);
		db.writeBytes(m);

		var seed = SecureRandom.getSecureRandomBytes(mgf1SeedLength);
		var dbMask = mgf1(seed, n - mgf1SeedLength - 1);
		db = xorByteArrays(db, dbMask);

		var maskedSeed = xorByteArrays(seed, mgf1(db, mgf1SeedLength));

		var em = new ByteArray();
		em.writeByte(0);
		em.writeBytes(maskedSeed);
		em.writeBytes(db);

		trace("  em length: " + em.length);
		//trace("  em bytes: " + em.toString());

		return em;
	}

	public function unpad(src:BigInteger, n:Int32, type:Int32 = 0x02, originalMessage:ByteArray = null):ByteArray {
		// Convert BigInteger to byte array properly
		var emRaw = src.toByteArray();
		var em = new ByteArray();
		em.position = 0;
		
		// Pad with leading zeros if needed
		var paddingNeeded = n - emRaw.length;
		trace("OAEP unpad debug:");
		trace("  n (key size in bytes): " + n);
		trace("  emRaw length: " + emRaw.length);
		trace("  paddingNeeded: " + paddingNeeded);
		
		// Ensure we don't have negative padding
		if (paddingNeeded > 0) {
			for (i in 0...paddingNeeded) {
				em.writeByte(0);
			}
		}
		em.writeBytes(emRaw);
		
		if (em.length != n) {
			throw new TLSError("OAEP::unpad: Invalid length after padding", TLSError.decode_error);
		}

		// Validate leading zero
		if (em.get(0) != 0) {
			throw new TLSError("OAEP::unpad: Invalid leading byte", TLSError.decode_error);
		}

		// Extract masked components
		var maskedSeed = new ByteArray();
		for (i in 0...mgf1SeedLength) {
			maskedSeed.writeByte(em.get(i + 1));
		}
		
		var maskedDB = new ByteArray();
		for (i in 0...(em.length - mgf1SeedLength - 1)) {
			maskedDB.writeByte(em.get(i + mgf1SeedLength + 1));
		}

		// Compute seed and db
		var seedMask = mgf1(maskedDB, mgf1SeedLength);
		var seed = xorByteArrays(maskedSeed, seedMask);

		var dbMask = mgf1(seed, n - mgf1SeedLength - 1);
		var db = xorByteArrays(maskedDB, dbMask);

		// Verify lHash
		var dbLHash = new ByteArray();
		for (i in 0...mgf1SeedLength) {
			dbLHash.writeByte(db.get(i));
		}
		
		var lHash = hash.hash(new ByteArray());
		if (!byteArrayEquals(dbLHash, lHash)) {
			throw new TLSError("OAEP::unpad: lHash mismatch", TLSError.decode_error);
		}

		// Extract message
		var i = mgf1SeedLength;
		while (i < db.length && db.get(i) == 0) i++;
		if (i == db.length || db.get(i) != 1) {
			throw new TLSError("OAEP::unpad: Invalid padding", TLSError.decode_error);
		}

		var m = new ByteArray();
		for (j in (i + 1)...db.length) {
			m.writeByte(db.get(j));
		}
		
		trace("OAEP unpad result:");
		trace("  message length: " + m.length);
		//trace("  message bytes: " + m.toString());
		
		return m;
	}

	private function mgf1(seed:ByteArray, len:Int):ByteArray {
		var t = new ByteArray();
		var counter = 0;
		while (t.length < len) {
			var c = new ByteArray();
			c.writeBytes(seed);
			c.writeUnsignedInt(counter);
			var h = hash.hash(c);
			t.writeBytes(h);
			counter++;
		}
		return t.sub(0, len);
	}

	private function xorByteArrays(a:ByteArray, b:ByteArray):ByteArray {
		var result = new ByteArray();
		var minLen = (a.length < b.length) ? a.length : b.length;
		for (i in 0...minLen) {
			result.writeByte(a.get(i) ^ b.get(i));
		}
		return result;
	}

	private function byteArrayEquals(a:ByteArray, b:ByteArray):Bool {
		if (a.length != b.length)
			return false;
		for (i in 0...a.length) {
			if (a.get(i) != b.get(i))
				return false;
		}
		return true;
	}
}