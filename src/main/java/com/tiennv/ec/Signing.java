package com.tiennv.ec;

import java.math.BigInteger;

public class Signing {
    private Point publicKey;
    private BigInteger s;

    public Signing(Point publicKey, BigInteger s) {
        this.publicKey = publicKey;
        this.s = s;
    }

    public Point getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Point publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getS() {
        return s;
    }

    public void setS(BigInteger s) {
        this.s = s;
    }
}
