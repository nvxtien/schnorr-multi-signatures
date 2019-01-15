package com.tiennv.ec;

public class TCommitment {
    private final Point publicKey;
    private final byte[] t;

//    public TCommitment() {}

    public TCommitment(Point publicKey, byte[] t) {
        this.publicKey = publicKey;
        this.t = t;
    }

    public Point getPublicKey() {
        return publicKey;
    }

    public byte[] getT() {
        return t;
    }
}
