package com.tiennv.ec;

import org.junit.Test;

import java.math.BigInteger;

public class PublicKeyTest {

    @Test
    public void publicKeyTest() {
        BigInteger pubKey = new BigInteger("143");
        System.out.println(pubKey.toString(8));

        pubKey = new BigInteger("21");
        System.out.println(pubKey.toString(8));
    }
}
