package com.tiennv.ec;

import java.math.BigInteger;

public class Signature {
    private final Point r;
    private final BigInteger s;

    public Signature(Point r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public Point getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }

}
