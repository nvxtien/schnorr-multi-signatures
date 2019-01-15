package com.tiennv.ec;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * m = Message
 * x = Private key
 * G = Generator point
 * X = Public key (X = x*G, public key = private key * generator point)
 *
 * H(x, y, z..) = Cryptographic Hashing function
 * R = random nonce * generator point
 * s = random nonce + Hash function(Users Public Key, Random point on Elliptic Curve, the message (transaction)) * Private Key
 * (R, s) = (r*G, r + H(X, R, m) * x)
 *
 * (R, s) = Signature (R is the x co-ordinate of a random value after multiplying by the generator point, s is the signature)
 *
 * Signature verification:
 * s*G = R + H(X,R,m) * X
 * = G*(r + H(X, R, m) * x) = r*G + H(X, R, m) * x * G = R + H(X, R, m) * X
 *
 * http://web.stanford.edu/class/cs259c/lectures/schnorr.pdf
 *
 * Key Generation:
 * 1/ Choose an elliptic curve E over a finite field Fq.
 * 2/ Choose a random point P ← E(Fq).
 * 3/ Choose a random integer a ← [1, r] where r is the order of P.
 * 4/ Choose a hash function H : {0, 1} → [1, r].
 * 5/ Output pk = (P, Q = [a]P) and sk = (a, pk).
 *
 * Signing(sk, M)
 * 1/ Choose random k ← [1, r] and set R = [k]P.
 * 2/ Set e = H(M||R).
 * 3/ Set s = k + ae (mod r).
 * 4/ Output the signature σ = (R, s).
 *
 * Verification(pk, σ = (R, s))
 * 1/ Compute e = H(M||R).
 * 2/ If R + [e]Q = [s]P, output “accept”; else output “reject”.
 *
 */
public class SchnorrSignatures {

    public PrivateKey generateKeyPair() {
        return Secp256k1.generateKeyPair(256);
    }

    public Signature sign(PrivateKey sk, byte[] m) {

        SecureRandom random = new SecureRandom();
        BigInteger k = new BigInteger(256, random);
        Point r = Secp256k1.G.scalarMultiply(k);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        BigInteger input = new BigInteger(m);
        BigInteger rencode = new BigInteger(r.toString().getBytes());
        byte[] h = digest.digest(input.or(rencode).toByteArray());
        BigInteger e =  new BigInteger(h);

        BigInteger s = k.add(sk.getKey().multiply(e)).mod(Secp256k1.n);

        Signature signature = new Signature(r, s);

        return signature;
    }


    public boolean verify(Point q, Signature signature, byte[] m) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        BigInteger input = new BigInteger(m);
        BigInteger rencode = new BigInteger(signature.getR().toString().getBytes());

        byte[] h = digest.digest(input.or(rencode).toByteArray());
        BigInteger e =  new BigInteger(h);

        Point req = signature.getR().add(q.scalarMultiply(e));
        Point sP = Secp256k1.G.scalarMultiply(signature.getS());

        return  req.equals(sP);
    }

    public void create() {

        String m = "message";

        PrivateKey priv = Secp256k1.generateKeyPair(160);
        Point pub = priv.getPublicKey().getPoint();

        SecureRandom secureRandom = new SecureRandom();
        BigInteger nonce = new BigInteger(160, secureRandom);
        Point R = Secp256k1.G.scalarMultiply(nonce);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        BigInteger msg = new BigInteger(m.getBytes());
        System.out.println(m);
        BigInteger sum = pub.getAffineX().or(R.getAffineX()).or(msg);

        byte[] encodedhash = digest.digest(sum.toByteArray());

        BigInteger H = new BigInteger(encodedhash);


        BigInteger s = nonce.add(H.and(priv.getKey()));


        BigInteger Hx = H.and(priv.getKey());
        Point HxG = Secp256k1.G.scalarMultiply(Hx);

        // (R, S)

        // Signature verification:
        // s*G = R + H(X,R,m) * X

//        Point HX =  pub.multiplyScalar(H);
//        EFp eFp = new EFp();

        //R + H(X,R,m) * X
        Point right = R.add(pub.scalarMultiply(H));

        Point left = Secp256k1.G.scalarMultiply(s);

        System.out.println(left.equals(right));

    }

}
