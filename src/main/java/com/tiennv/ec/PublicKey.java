package com.tiennv.ec;

import java.math.BigInteger;

/**
 * https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki
 *
 */
public class PublicKey {
    private String key;
    private Point q;

    private BigInteger x, y;

    public PublicKey(Point q) {
        this.x = q.getAffineX();
        this.y = q.getAffineY();
        this.q = q;
    }

    public String getPublicKey() {

//        BigInteger prefix1 = new BigInteger("02", 16);

        BigInteger prefix = new BigInteger("02", 16).add(this.y.and(BigInteger.ONE));

        BigInteger xx = new BigInteger(this.x.toString(16), 16);
        System.out.println("xx " + xx);

        byte[] pub = MyUtil.concat(new byte[]{prefix.byteValue()}, this.x.toByteArray());

//        System.out.println(prefix);
//        byte[] prefix = {prefix};

//        System.out.println(new byte[]{prefix.byteValue()});
//
//        System.out.println(new BigInteger(new byte[]{prefix.byteValue()}));
//
        System.out.println(this.x.toString(16));
        return new BigInteger(pub).toString(16);
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
    public byte[] toBytes() {
        return this.x.toByteArray();
    }

    public String toBase58() {
        return Base58.encode(this.x.toByteArray());
    }
}
