package com.tiennv.ec;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.assertTrue;

public class MuSigTest {
    @Test
    public void multisetOfPublicKeysTest() {

        List<Point> pubKeys = new ArrayList<>();

        PrivateKey privateKey1 = Secp256k1.generateKeyPair(256);
        pubKeys.add(privateKey1.getPublicKey().getPoint());

        PrivateKey privateKey2 = Secp256k1.generateKeyPair(256);
        pubKeys.add(privateKey2.getPublicKey().getPoint());

        byte[] L = pubKeys.stream().map(Point::toString).collect(Collectors.joining()).getBytes();

        System.out.println(L.toString());
        System.out.println(L.length);
    }

    @Test
    public void gen() {

        PrivateKey privateKey = Secp256k1.generateKeyPair(256);
        final MuSig cosigner = new MuSig(privateKey);

        PrivateKey privateKey1 = Secp256k1.generateKeyPair(256);
        final MuSig cosigner1 = new MuSig(privateKey1);

        // X2,...,Xn be the public keys of other cosigners
        List<Point> pubKeys = new ArrayList<>();
        pubKeys.add(privateKey.getPublicKey().getPoint());

        List<Point> pubKeys1 = new ArrayList<>();
        pubKeys1.add(privateKey1.getPublicKey().getPoint());

        cosigner.setCosigners(pubKeys1);
        cosigner1.setCosigners(pubKeys);

        Point pointX = cosigner.computeAggPubKeys();
        Point pointX1 = cosigner1.computeAggPubKeys();

        assertTrue(pointX.equals(pointX1));

        // t commitment
        TCommitment tCommitment = cosigner.sendTComm();
        cosigner1.receiveTComm(tCommitment);

        TCommitment tCommitment1 = cosigner1.sendTComm();
        cosigner.receiveTComm(tCommitment1);

        // R commitment
        RCommitment rCommitment = cosigner.sendRComm();
        cosigner1.receiveRComm(rCommitment);

        RCommitment rCommitment1 = cosigner1.sendRComm();
        cosigner.receiveRComm(rCommitment1);

        Point aggR = cosigner.computeAggR();
        Point aggR1 = cosigner1.computeAggR();

        assertTrue(aggR.equals(aggR1));

        String m = "message";
        cosigner.sign(m.getBytes());
        cosigner1.sign(m.getBytes());

        Signing signing = cosigner.sendSig();
        cosigner1.receiveSig(signing);

        Signing signing1 = cosigner1.sendSig();
        cosigner.receiveSig(signing1);

        MultiSignatures signatures = cosigner.multisign();
        System.out.println(cosigner.verify());

        MultiSignatures signatures1 = cosigner1.multisign();
        cosigner1.verify();
        System.out.println(cosigner1.verify());

        assertTrue(signatures.getS().equals(signatures1.getS()));
    }
}
