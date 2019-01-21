package com.tiennv.ec;

import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

public class PublicKeyTest {

    @Test
    public void publicKeyTest() {

        PrivateKey privateKey = Secp256k1.generateKeyPair(256);

        PublicKey publicKey = privateKey.getPublicKey();
        System.out.println(publicKey.getAffine());

        /*byte[] pubKey = publicKey.toBytes();

        String text = null;
        try {
            text = new String(pubKey, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

//        System.out.println(text);
        String b58 = publicKey.toBase58();
        System.out.println(b58);

        byte[] decode = null;
        try {
            decode = Base58.decode(publicKey.toBase58());
            System.out.println(new BigInteger(decode));
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            System.out.println(Base58.encode(decode));
        } catch (Exception e) {
            e.printStackTrace();
        }
*/
        System.out.println(publicKey.getPublicKey());


//        BigInteger pubKey = new BigInteger("143");
//        System.out.println(pubKey.toString(8));
//
//        pubKey = new BigInteger("21");
//        System.out.println(pubKey.toString(8));
    }
}
