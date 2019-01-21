package com.tiennv.ec;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class PublicKeyTest {

    @Test
    public void publicKeyTest() {

        PrivateKey privateKey = Secp256k1.generateKeyPair(256);

        PublicKey publicKey = privateKey.getPublicKey();
        byte[] pubKey = publicKey.toBytes();

        String text = null;
        try {
            text = new String(pubKey, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        System.out.println(text);


//        BigInteger pubKey = new BigInteger("143");
//        System.out.println(pubKey.toString(8));
//
//        pubKey = new BigInteger("21");
//        System.out.println(pubKey.toString(8));
    }
}
