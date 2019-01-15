package com.tiennv.ec;

import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class SchnorrSignaturesTest {
    @Test
    public void SchnorrSignatures() {
        SchnorrSignatures signatures = new SchnorrSignatures();
        PrivateKey privateKey = signatures.generateKeyPair();
        Signature sig = signatures.sign(privateKey, "hello".getBytes());
        boolean expected = signatures.verify(privateKey.getPublicKey().getPoint(), sig, "hello".getBytes());
        assertTrue(expected);
    }
}
