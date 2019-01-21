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
        //        this.key = "04".concat(q.getAffineX().toString(16).concat(q.getAffineY().toString(16)));
//        this.q = q;
    }

    public Point getPoint() {
        return this.q;
    }

    public String getEncodedValue() {
        return this.key;
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
}
