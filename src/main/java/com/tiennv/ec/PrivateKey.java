package com.tiennv.ec;

import java.math.BigInteger;

public class PrivateKey {

    private BigInteger key;
    private PublicKey publicKey;

    public PrivateKey(BigInteger priv, Point r) {
        this.key = priv;
        this.publicKey = new PublicKey(r);
    }

    public BigInteger getKey() {
        return key;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public String toString() {
        return "PrivateKey{" +
                "key=" + key +
                '}';
    }
}
