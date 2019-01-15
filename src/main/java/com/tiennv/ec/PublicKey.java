package com.tiennv.ec;

public class PublicKey {
    private String key;
    private Point q;

    public PublicKey(Point q) {
        this.key = "04".concat(q.getAffineX().toString(16).concat(q.getAffineY().toString(16)));
        this.q = q;
    }

    public Point getPoint() {
        return this.q;
    }

    public String getEncodedValue() {
        return this.key;
    }
}
