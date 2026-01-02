package com.hurlant.crypto.pad;

import com.hurlant.util.Std2;
import haxe.Int32;
import com.hurlant.crypto.prng.SecureRandom;
import com.hurlant.math.BigInteger;
import com.hurlant.util.ByteArray;
import com.hurlant.crypto.tls.TLSError;

class PKCS1 {

	public function new() {

	}
	
	// RSA-compatible padding for encryption/signing: ByteArray -> Int32 -> Int32 -> Int32 -> ByteArray
	public function pad(src:ByteArray, end:Int32, n:Int32, type:Int32 = 0x02):ByteArray {
		var out = new ByteArray();
		var p = src.position;
		end = Std.int(Std2.min3(end, src.length, p + n - 11));
		src.position = end;
		var i = end - 1;
		while (i >= p && n > 11)
			out[--n] = src[i--];
		out[--n] = 0;
		if (type == 0x02) {
			var rngBytes = SecureRandom.getSecureRandomBytes(n - 2);
			var rngIndex = 0;
			while (n > 2) {
				var x = rngBytes.get(rngIndex++); // Use get() instead of array access
				if (x == 0)
					x = 1; // Ensure non-zero (PKCS#1 requirement)
				out[--n] = x;
			}
		} else {
			while (n > 2)
				out[--n] = 0xFF;
		}
		out[--n] = type;
		out[--n] = 0;
		return out;
	}

	// RSA-compatible unpadding for decryption/verification: BigInteger -> Int32 -> Int32 -> ByteArray -> ByteArray
	public function unpad(src:BigInteger, n:Int32, type:Int32 = 0x02, originalMessage:ByteArray = null):ByteArray {
		// PKCS#1 ignores originalMessage, so no change needed
		var out = new ByteArray();
		var b = new ByteArray();
		src.toArray(b);

		b.position = 0;
		var i = 0;
		while (i < b.length && b[i] == 0)
			++i;

		if (b.length - i != n - 1 || b[i] != type) {
			trace("PKCS#1 unpad: i=" + i + ", expected b[i]==" + type + ", got b[i]=${b[i]}");
			return null;
		}
		++i;
		while (b[i] != 0) {
			if (++i >= b.length) {
				trace("PKCS#1 unpad: i=" + i + ", b[i-1]!=0 (=" + Std.string(b[i - 1]) + ")");
				return null;
			}
		}
		while (++i < b.length) {
			out.writeByte(b[i]);
		}
		out.position = 0;
		return out;
	}
}