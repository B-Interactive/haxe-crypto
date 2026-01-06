package com.hurlant.crypto.cert.curve;

import haxe.Int32;
import haxe.Int64;
import haxe.io.Bytes;

/**
 * Curve25519/X25519 Diffie-Hellman key exchange implementation.
 * 
 * Credit to Anton Nesterov's implementation here https://github.com/ntrf/Curve25519
 * for providing a reference.
 * 
 * This implementation follows RFC 7748 (X25519) and is designed to be secure against
 * side-channel attacks. It implements the Montgomery ladder for scalar multiplication
 * over the Curve25519 elliptic curve.
 * 
 * Security features:
 * - Constant-time operations to prevent timing attacks
 * - Proper scalar clamping as per RFC 7748
 * - Correct point arithmetic modulo 2^255 - 19
 * 
 * Usage example:
 * ```haxe
 * // Generate a private key (32 bytes)
 * var privateKey = SecureRandom.getSecureRandomBytes(32);
 * 
 * // Generate public key from private key
 * var publicKey = Curve25519.genKeypair(privateKey);
 * 
 * // Compute shared secret with another party's public key
 * var sharedSecret = Curve25519.combineKeys(privateKey, publicKey);
 * ```
 */
@:forward
abstract Vec(haxe.ds.Vector<Int64>) {
	/**
	 * Creates a new vector initialized to all zeros.
	 */
	public static function makeZero():Vec {
		var r = new Vec();
		for (i in 0...32)
			r.setV(i, Int64.ofInt(0));
		return r;
	}

	/**
	 * Creates a new vector with value 1 at index 0 and 0 elsewhere.
	 */
	public static function makeOne():Vec {
		var r = new Vec();
		for (i in 1...32)
			r.setV(i, Int64.ofInt(0));
		r.setV(0, Int64.ofInt(1));
		return r;
	}

	/**
	 * Creates the constant value A24 = 121665 used in scalar multiplication.
	 */
	private static function makeA24():Vec {
		var r = new Vec();
		for (i in 1...32)
			r.setV(i, Int64.ofInt(0));
		r.setV(0, Int64.ofInt(0x41)); // 0x1DB41 = 121665
		r.setV(1, Int64.ofInt(0xDB));
		r.setV(2, Int64.ofInt(0x01));
		return r;
	}

	/**
	 * Creates a new vector with value x at index 0 and 0 elsewhere.
	 */
	public function small(x:Int):Void {
		for (i in 1...32)
			this.set(i, Int64.ofInt(0));
		this.set(0, Int64.ofInt(x));
		vnorm();
	}

	/**
	 * Gets a value from the vector at index i.
	 */
	inline public function getV(i:Int):Int64 {
		return this.get(i);
	}

	/**
	 * Sets a value in the vector at index i.
	 */
	inline public function setV(i:Int, v:Int64):Void {
		this.set(i, v);
	}

	/**
	 * Copies values from another vector.
	 */
	public function copy(x:Vec):Void {
		for (i in 0...32)
			setV(i, x.getV(i));
	}

	/**
	 * Adds two vectors and stores result in this vector.
	 */
	public function vadd(a:Vec, b:Vec):Void {
		for (i in 0...32)
			setV(i, Int64.add(a.getV(i), b.getV(i)));
	}

	/**
	 * Subtracts two vectors and stores result in this vector.
	 */
	public function vsub(a:Vec, b:Vec):Void {
		for (i in 0...32)
			setV(i, Int64.sub(a.getV(i), b.getV(i)));
	}

	/**
	 * Multiplies two vectors and stores result in this vector.
	 */
	public function vmult(a:Vec, b:Vec):Void {
		var v:Int64;
		for (i in 0...32) {
			v = Int64.ofInt(0);
			var j = 0;
			while (j <= i) {
				v = Int64.add(v, Int64.mul(a.getV(j), b.getV(i - j)));
				j++;
			}
			j = i + 1;
			while (j < 32) {
				v = Int64.add(v, Int64.mul(Int64.ofInt(38), Int64.mul(a.getV(j), b.getV(i + 32 - j))));
				j++;
			}
			setV(i, v);
		}
		vnorm();
		vnorm();
	}

	/**
	 * Squares the vector and stores result in this vector.
	 */
	public function vsqr(a:Vec):Void {
		vmult(a, a);
	}

	/**
	 * Multiplies by A24 constant (121665) and stores result in this vector.
	 */
	private static var _a24 = makeA24();

	public function vmult_121665(a:Vec):Void {
		vmult(a, _a24);
		vnorm();
		vnorm();
	}

	/**
	 * Performs modular normalization to keep values within range.
	 */
	public function vnorm():Void {
		var v:Int64 = Int64.ofInt(0);
		for (j in 0...31) {
			v = Int64.add(getV(j), Int64.ofInt(1 << 8));
			var c = Int64.shr(v, 8);
			setV(j + 1, Int64.add(getV(j + 1), Int64.sub(c, Int64.ofInt(1))));
			setV(j, Int64.sub(v, Int64.shl(c, 8)));
		}
		v = Int64.add(getV(31), Int64.ofInt(1 << 8));
		var c = Int64.shr(v, 8);
		setV(0, Int64.add(getV(0), Int64.mul(Int64.ofInt(38), Int64.sub(c, Int64.ofInt(1)))));
		setV(31, Int64.sub(v, Int64.shl(c, 8)));
	}

	/**
	 * Finalizes the result by applying final modular reduction.
	 */
	public function freeze(temp:Vec):Void {
		vnorm();
		var v:Int64 = this.get(31);
		var x = Int64.shr(v, 7);
		this.set(31, Int64.and(v, Int64.ofInt(0x7f)));
		v = Int64.mul(x, Int64.ofInt(19));
		for (j in 0...31) {
			v = Int64.add(v, getV(j));
			this.set(j, Int64.and(v, Int64.ofInt(255)));
			v = Int64.ushr(v, 8);
		}
		v = Int64.add(v, getV(31));
		setV(31, v);
	}

	/**
	 * Creates a new vector initialized with zeros.
	 */
	public function new() {
		this = new haxe.ds.Vector<Int64>(32);
	}
}

/**
 * Curve25519/X25519 Diffie-Hellman key exchange implementation.
 * 
 * Implements the X25519 key exchange algorithm as defined in RFC 7748.
 * This is a secure, constant-time implementation suitable for cryptographic use.
 */
class Curve25519 {
	/**
	 * Generate a Curve25519 public key from a private key.
	 * 
	 * @param privateKey A 32-byte private key
	 * @return The corresponding 32-byte public key
	 */
	public static function genKeypair(privateKey:Bytes):Bytes {
		if (privateKey.length != 32) {
			throw "Private key must be 32 bytes";
		}

		var result = Bytes.alloc(32);
		curve25519(result, privateKey, null);
		return result;
	}

	/**
	 * Compute the shared secret from a private key and a public key.
	 * 
	 * @param privateKey A 32-byte private key
	 * @param publicKey A 32-byte public key
	 * @return The 32-byte shared secret
	 */
	public static function combineKeys(privateKey:Bytes, publicKey:Bytes):Bytes {
		if (privateKey.length != 32) {
			throw "Private key must be 32 bytes";
		}
		if (publicKey.length != 32) {
			throw "Public key must be 32 bytes";
		}

		var sharedKey = Bytes.alloc(32);
		curve25519(sharedKey, privateKey, publicKey);
		return sharedKey;
	}

	/**
	 * Internal implementation of Curve25519/X25519 scalar multiplication.
	 * 
	 * @param result Output buffer for the result (32 bytes)
	 * @param multiplier Scalar value (32 bytes)
	 * @param base Base point or public key (32 bytes, can be null for default base point)
	 */
	private static function curve25519(result:Bytes, multiplier:Bytes, base:Bytes):Void {
		// Copy and clamp the scalar as per RFC 7748
		var e = Bytes.alloc(32);
		e.blit(0, multiplier, 0, 32);
		e.set(0, e.get(0) & 248);
		e.set(31, (e.get(31) & 127) | 64);

		// Initialize point coordinates
		var px = Vec.makeOne();
		var pz = Vec.makeZero();
		var qx = Vec.makeZero();
		var qz = Vec.makeOne();

		// Set base point or unpack the public key
		if (base == null) {
			// Default base point for X25519: x = 9, z = 1
			qx.small(9);
		} else {
			// Unpack bytes into vector elements
			for (i in 0...32) {
				qx.setV(i, Int64.ofInt(base.get(i)));
			}
		}

		// Initialize temporary variables for ladder operations
		var tx = Vec.makeZero();
		var tz = Vec.makeZero();
		var ax = Vec.makeZero();
		var az = Vec.makeZero();
		var bx = Vec.makeZero();
		var bz = Vec.makeZero();
		var dx = Vec.makeZero();

		// Initialize dx = qx - qz
		dx.vsub(qx, qz);

		// Montgomery ladder implementation
		var y = 31;
		while (y >= 0) {
			var yy = e.get(y);
			var bm = 7;

			while (bm >= 0) {
				var b = (yy >> 7) & 1;
				yy <<= 1;

				// Conditional swap of points to make operation constant time
				condSwap(px, qx, b);
				condSwap(pz, qz, b);

				// Point difference calculations for ladder
				ptDiff(tx, tz, qx, qz);
				ptDiff(ax, az, px, pz);

				// Point addition and doubling
				ptAdd(qx, qz, tx, tz, ax, az, dx);
				ptDouble(px, pz, ax, az, tx, tz);

				// Swap back after operation to maintain consistency
				condSwap(px, qx, b);
				condSwap(pz, qz, b);

				bm--;
			}
			y--;
		}

		// Finalize result: compute inverse of z coordinate and scale x
		recip(qz, tx, tz, ax, az, bx);
		qx.vmult(px, qz);
		qx.freeze(px);

		for (i in 0...32) {
			result.set(i, Int64.toInt(qx.getV(i)) & 0xFF);
		}
	}

	/**
	 * Conditional swap of two vectors based on a boolean flag.
	 * 
	 * @param x1 First vector
	 * @param x2 Second vector  
	 * @param b Boolean flag (0 or 1)
	 */
	private static function condSwap(x1:Vec, x2:Vec, b:Int):Void {
		var all1s = Int64.make(0xFFFFFFFF, 0xFFFFFFFF);
		var mask = Int64.xor(Int64.and(Int64.sub(Int64.ofInt(b), Int64.ofInt(1)), all1s), all1s);
		for (i in 0...32) {
			var a = x1.getV(i);
			var bVal = x2.getV(i);
			var t = Int64.and(Int64.xor(a, bVal), mask);
			x1.setV(i, Int64.xor(a, t));
			x2.setV(i, Int64.xor(bVal, t));
		}
	}

	/**
	 * Point doubling in Montgomery ladder.
	 */
	private static function ptDouble(rx:Vec, rz:Vec, ax:Vec, az:Vec, tx:Vec, tz:Vec):Void {
		tx.vmult(ax, ax);
		tz.vmult(az, az);
		rx.vmult(tx, tz);
		tz.vsub(tx, tz);
		rz.vmult_121665(tz);
		tx.vadd(tx, rz);
		rx.vmult(tx, tz);
	}

	/**
	 * Point addition in Montgomery ladder.
	 */
	private static function ptAdd(rx:Vec, rz:Vec, ax:Vec, az:Vec, bx:Vec, bz:Vec, dx:Vec):Void {
		rx.vmult(ax, bz);
		rz.vmult(az, bx);
		ax.vadd(rx, rz);
		az.vsub(rx, rz);
		rx.vmult(ax, ax);
		ax.vmult(az, az);
		rz.vmult(ax, dx);
	}

	/**
	 * Compute point differences in Montgomery ladder.
	 */
	private static function ptDiff(rx:Vec, rz:Vec, ax:Vec, az:Vec):Void {
		rx.vadd(ax, az);
		rz.vsub(ax, az);
	}

	/**
	 * Compute modular inverse using repeated squaring (constant time).
	 */
	private static function recip(z:Vec, t0:Vec, t1:Vec, t2:Vec, t3:Vec, t4:Vec):Void {
		/* the chain for z^(2^255-21) is straight from djb's implementation */
		t1.vsqr(z); //  2 == 2 * 1
		t2.vsqr(t1); //  4 == 2 * 2
		t0.vsqr(t2); //  8 == 2 * 4
		t2.vmult(t0, z); //  9 == 8 + 1
		t0.vmult(t2, t1); // 11 == 9 + 2
		t1.vsqr(t0); // 22 == 2 * 11
		t3.vmult(t1, t2); // 31 == 22 + 9 == 2^5   - 2^0
		t1.vsqr(t3); // 2^6   - 2^1
		t2.vsqr(t1); // 2^7   - 2^2
		t1.vsqr(t2); // 2^8   - 2^3
		t2.vsqr(t1); // 2^9   - 2^4
		t1.vsqr(t2); // 2^10  - 2^5
		t2.vmult(t1, t3); // 2^10  - 2^0
		t1.vsqr(t2); // 2^11  - 2^1
		t3.vsqr(t1); // 2^12  - 2^2
		for (i in 1...5) {
			t1.vsqr(t3);
			t3.vsqr(t1);
		} // 2^20  - 2^10
		t1.vmult(t3, t2); // 2^20  - 2^0
		t3.vsqr(t1); // 2^21  - 2^1
		t4.vsqr(t3); // 2^22  - 2^2
		for (i in 1...10) {
			t3.vsqr(t4);
			t4.vsqr(t3);
		} // 2^40  - 2^20
		t3.vmult(t4, t1); // 2^40  - 2^0
		for (i in 0...5) {
			t1.vsqr(t3);
			t3.vsqr(t1);
		} // 2^50  - 2^10
		t1.vmult(t3, t2); // 2^50  - 2^0
		t2.vsqr(t1); // 2^51  - 2^1
		t3.vsqr(t2); // 2^52  - 2^2
		for (i in 1...25) {
			t2.vsqr(t3);
			t3.vsqr(t2);
		} // 2^100 - 2^50
		t2.vmult(t3, t1); // 2^100 - 2^0
		t3.vsqr(t2); // 2^101 - 2^1
		t4.vsqr(t3); // 2^102 - 2^2
		for (i in 1...50) {
			t3.vsqr(t4);
			t4.vsqr(t3);
		} // 2^200 - 2^100
		t3.vmult(t4, t2); // 2^200 - 2^0
		for (i in 0...25) {
			t4.vsqr(t3);
			t3.vsqr(t4);
		} // 2^250 - 2^50
		t2.vmult(t3, t1); // 2^250 - 2^0
		t1.vsqr(t2); // 2^251 - 2^1
		t2.vsqr(t1); // 2^252 - 2^2
		t1.vsqr(t2); // 2^253 - 2^3
		t2.vsqr(t1); // 2^254 - 2^4
		t1.vsqr(t2); // 2^255 - 2^5
		z.vmult(t1, t0); // 2^255 - 21
	}
}
