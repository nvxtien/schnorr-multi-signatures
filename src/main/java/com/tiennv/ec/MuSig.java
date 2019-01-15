package com.tiennv.ec;

import sun.nio.cs.ext.DoubleByte;
import sun.text.normalizer.UTF16;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;

/**
 * https://eprint.iacr.org/2018/068.pdf
 *
 * Signing:
 * L = {Xi} multiset of all public keys
 * ai = Hagg(L,Xi) the signer computes with its public key Xi
 */
public class MuSig {

    private RCommitment rCommitment;
    private PrivateKey privateKey;

    private List<TCommitment> tCommitments = new ArrayList<>();
    private List<RCommitment> rCommitments = new ArrayList<>();

    // The list of public keys of cosigners
    private List<Point> cosigners = new ArrayList<>();

    private Point aggregatedPubKeys;
    private BigInteger rnonce;
    private byte[] ai;
    private BigInteger s;
    private List<BigInteger> sigs = new ArrayList<>();

    private byte[] multisetL;

    private Point aggR;
    private byte[] m;
    private MultiSignatures signatures;

    public MuSig(final PrivateKey privateKey) {
        this.privateKey = privateKey;
        this.cosigners.add(privateKey.getPublicKey().getPoint());
        System.out.println("Public key: " + this.cosigners);
    }

    private byte[] aggH(final byte[] L, final Point pub) {
        return hash(concat(L, pub.toString().getBytes()));
    }

    private Point computeXa(final byte[] L, final Point pub) {
        byte[] a = aggH(L, pub);
//        System.out.println("compute a: " + new BigInteger(a));
        BigInteger intA = toUnsignedBigInteger(a);
//        this.ai = intA.toString().getBytes();
        System.out.println("compute this.ai: " + intA);

        return pub.scalarMultiply(intA);
    }

    private BigInteger toUnsignedBigInteger(byte[] a) {
        BigInteger intA = new BigInteger(a);
        if (intA.signum() == -1) {
            intA = intA.negate();
        }
        return intA;
    }

    public Point computeAggPubKeys() {
        byte[] L = multisetOfPublicKeys(cosigners);
        Optional<Point> optPubKeys = cosigners.stream().map(pub -> computeXa(L, pub)).reduce((x, y) -> x.add(y));
        Point aggregatedPubKeys = optPubKeys.get();
        this.aggregatedPubKeys = aggregatedPubKeys;

        byte[] a = aggH(L, this.privateKey.getPublicKey().getPoint());
        this.ai = a;

        return aggregatedPubKeys;
    }

    public byte[] sigH(byte[] input) {
        return  hash(input);
    }

    private byte[] comH(Point pR) {
        return hash(pR.toString().getBytes());
    }

    private byte[] multisetOfPublicKeys(List<Point> pubKeys) {
        this.multisetL = pubKeys.stream().map(Point::toString).collect(Collectors.joining()).getBytes();
        return multisetL;
    }

    public byte[] hash(byte[] input) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digest.digest(input);
    }

    private TCommitment computeTComm() {
        SecureRandom random = new SecureRandom();
        rnonce = new BigInteger(256, random);
        Point pR = Secp256k1.G.scalarMultiply(rnonce);
        byte[] t = comH(pR);
        this.rCommitment = new RCommitment(this.privateKey.getPublicKey().getPoint(), pR);
        return new TCommitment(this.privateKey.getPublicKey().getPoint(), t);
    }

    public Point computeAggR() {
        Optional<Point> optR = this.rCommitments.stream().map(x -> x.getR()).reduce((x, y) -> x.add(y));
        Point aggR = optR.get();
        this.aggR = aggR;
        return aggR;
    }

    private byte[] concat(final byte[] a, final byte[] b) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(a);
            outputStream.write(b);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    public TCommitment sendTComm() {
        TCommitment tCommitment = computeTComm();
        tCommitments.add(tCommitment);
        return tCommitment;
    }

    public void receiveTComm(final TCommitment tCommitment) {
        tCommitments.add(tCommitment);
    }

    public RCommitment sendRComm() {
        // Upon reception of commitments t2,...,tn from other cosigners, it sends R1
        this.rCommitments.add(this.rCommitment);
        return this.rCommitment;
    }

    public void receiveRComm(final RCommitment rCommitment) {
        // Upon reception of R2,...,Rn from other cosigners, it checks that ti = Hcom(Ri)
        // for all i ∈{2,...,n} and aborts the protocol if this is not the case
        final Point pR = rCommitment.getR();
        List<TCommitment> tcomm = this.tCommitments.stream().filter(x -> x.getPublicKey().equals(rCommitment.getPub())).collect(Collectors.toList());
        if (tcomm.size() == 1) {
            byte[] rh =  comH(pR);
            if (Arrays.equals(tcomm.get(0).getT(), rh)) {
                this.rCommitments.add(rCommitment);
            }
        }
    }

    public void setCosigners(final List<Point> pubKeys) {
        this.cosigners.addAll(pubKeys);
//        System.out.println(this.cosigners);
        this.cosigners.sort(Comparator.comparing(Point::getAffineY));
        System.out.println(this.cosigners);
//        this.aggregatedPubKeys = computeAggPubKeys(cosigners);
    }

    public BigInteger sign(final byte[] m) {
//        Optional<Point> optR = this.rCommitments.stream().map(RCommitment::getR).reduce((x, y) -> x.add(y));
//        Point aggR = optR.get();

        String msg = new String(m);
        System.out.println("signing with m: " + msg);

        byte[] XR = concat(this.aggregatedPubKeys.toString().getBytes(), this.aggR.toString().getBytes());
        byte[] XRm = concat(XR, m);
        byte[] c = sigH(XRm);
        BigInteger intC = toUnsignedBigInteger(c);
        System.out.println("signing with c: " + intC);

        BigInteger intA = toUnsignedBigInteger(this.ai);
        System.out.println("signing with a: " + intA);

        BigInteger privateKey = this.privateKey.getKey();
        System.out.println("signing with private key: " + privateKey);

        BigInteger s = rnonce.add(intC.multiply(intA).multiply(privateKey)).mod(Secp256k1.n);

        System.out.println("signature s: " + s.toString());

        System.out.println("================ Self-verify the signature after it has been created======================");

        Point caPublicKey = this.privateKey.getPublicKey().getPoint().scalarMultiply(intC).scalarMultiply(intA);
//        System.out.println("caPublicKey: " + caPublicKey.toString());

        Point right = this.rCommitment.getR().add(caPublicKey);
        System.out.println(right);
        Point left = Secp256k1.G.scalarMultiply(s);
        System.out.println(left);

        System.out.println("Self-verify: " + right.equals(left));

        this.s = s;
        this.sigs.add(s);
        this.m = m;
        return s;
    }

    public Signing sendSig() {

        return new Signing(this.privateKey.getPublicKey().getPoint(), this.s);
    }

    public void receiveSig(Signing sign) {
        if (this.cosigners.contains(sign.getPublicKey())) {
            /**
             * Verification(pk, σ = (R, s))
             * 1/ Compute c = H(X~||R||m).
             * 2/ If R + [c][a]Q = [s]P, output “accept”; else output “reject”.
             */

            /**
             * sP = R + caQ
             */
            byte[] XR = concat(aggregatedPubKeys.toString().getBytes(), this.aggR.toString().getBytes());
            byte[] XRm = concat(XR, m);
            byte[] c = sigH(XRm);

            BigInteger intC = toUnsignedBigInteger(c);
            System.out.println("receiveSig c: " + intC);


            byte[] a = aggH(this.multisetL, sign.getPublicKey());
            BigInteger intA = toUnsignedBigInteger(a);

            System.out.println("receiveSig a: " + intA);

            List<RCommitment> rcomm = this.rCommitments.stream().filter(x -> x.getPub().equals(sign.getPublicKey())).collect(Collectors.toList());
            if (rcomm.size() == 1) {
                Point right = rcomm.get(0).getR().add(sign.getPublicKey().scalarMultiply(intC).scalarMultiply(intA));
                Point left = Secp256k1.G.scalarMultiply(sign.getS());
                if (right.equals(left)) {
                    System.out.println("Verify received signature: OK");
                    this.sigs.add(sign.getS());
                } else {
                    System.out.println("Verify received signature: KO");
                }
            }
        }
    }

    public MultiSignatures multisign() {
        System.out.println("signatures: " + sigs);
        Optional<BigInteger> optS = sigs.stream().reduce((x, y) -> x.add(y));
        BigInteger s = optS.get().mod(Secp256k1.n);
        MultiSignatures signatures = new MultiSignatures(this.aggR, s);
        this.signatures = signatures;
        return signatures;
    }

    public boolean verify() {
        // Note that verification is similar to standard Schnorr signatures
        // (with the public key included in the hash call)
        // with respect to the “aggregated” public key
        // R + [c]X~ = [s]P
        byte[] XR = concat(this.aggregatedPubKeys.toString().getBytes(), this.aggR.toString().getBytes());
        byte[] XRm = concat(XR, m);
        byte[] c = sigH(XRm);

        BigInteger intC = toUnsignedBigInteger(c);
        System.out.println("verify c: " + intC);

        Point left = this.aggR.add(this.aggregatedPubKeys.scalarMultiply(intC));
        Point right = Secp256k1.G.scalarMultiply(this.signatures.getS());
        return left.equals(right);
    }
}
