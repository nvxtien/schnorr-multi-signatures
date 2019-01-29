package com.tiennv.ec;

import com.google.common.io.BaseEncoding;
import com.tiennv.common.Base58;
import com.tiennv.common.MyUtil;

import java.math.BigInteger;

/**
 * https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *
 */
public class PublicKey {
    private Point q;

    private BigInteger x, y;
    private byte[] kBytes;
    private String pubKey;

    public PublicKey(String pubKey) {

        String value = pubKey.substring(2);
//        System.out.println("value " + value);
        this.x = new BigInteger(value, 16);

        BigInteger right = this.x.modPow(BigInteger.valueOf(3), Secp256k1.p).add(BigInteger.valueOf(7)).mod(Secp256k1.p);

        this.y = MyUtil.squareRoot(right, Secp256k1.p);

        BigInteger prefix = new BigInteger(pubKey.substring(0,2)).and(BigInteger.ONE);
        if (!this.y.and(BigInteger.ONE).equals(prefix)) {
            this.y = this.y.negate().mod(Secp256k1.p);
//            System.out.println("negate");
        }

        this.q = Point.newPoint(Secp256k1.Secp256k1, this.x, this.y);
    }

    public PublicKey(Point q) {
        this.x = q.getAffineX();
        this.y = q.getAffineY();
        this.q = q;

//        System.out.println("this.x.toByteArray() " + this.x.toByteArray().length);

        BigInteger prefix = BigInteger.valueOf(2).add(this.y.and(BigInteger.ONE));

        // a 32-byte hex number
        String hex = String.format("%064X", this.x);

        /*int n = 64 - hex.length();
        while (n > 0) {
            hex = "0".concat(hex);
            System.out.println("append 0 " + n);
            n--;
        }*/

        byte[] xCoor = BaseEncoding.base16().decode(hex);

//        System.out.println("prefix.toByteArray() " + prefix.toByteArray().length);
//        System.out.println("prefix.toByteArray() " + new BigInteger(prefix.toByteArray()));

        this.kBytes = MyUtil.concat(prefix.toByteArray(), xCoor);
        // The public key pk: a 33-byte array
        this.pubKey = String.format("%066X", new BigInteger(this.kBytes));

//        new BigInteger(this.kBytes).toString(16);
    }

    public String getPublicKey() {
        return this.pubKey;
    }

    public Point getPoint() {
        return this.q;
    }

    public String getAffine() {
        return this.q.toString();
    }

    public BigInteger getAffineX() {
        return this.q.getAffineX();
    }

    /**
     * The function bytes(P), where P is a point, returns bytes(0x02 + (y(P) & 1)) || bytes(x(P))
     *
     * This matches the compressed encoding for elliptic curve points used in Bitcoin already,
     * following section 2.3.3 of the SEC 1 standard (http://www.secg.org/sec1-v2.pdf).
     *
     * @return
     */
    public byte[] getBytes() {
        return this.kBytes;
    }

    public String toBase58() {
        return Base58.encode(getBytes());
    }
}
