package com.tiennv.ec;

import com.google.common.io.BaseEncoding;
import com.tiennv.common.MyUtil;

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
    private List<String> cosigners = new ArrayList<>();

    private PublicKey aggregatedPubKeys;
    private BigInteger rnonce;
    private byte[] ai;
    private BigInteger s;
    private List<BigInteger> sigs = new ArrayList<>();

    // the multiset3 of all their public keys
    // {Xn = g^xn}
    private byte[] multisetL;

    private PublicKey aggR;

    private byte[] m;
    private MultiSignatures signatures;

    public MuSig(final PrivateKey privateKey) {
        this.privateKey = privateKey;
        this.cosigners.add(privateKey.getPublicKey().getPublicKey());
        System.out.println("cosigner public key: " + this.cosigners);
    }

    /**
     * aggregatedKeyHash to compute the aggregated key
     * @param L
     * @param pub
     * @return
     */
    private byte[] aggregatedKeyHash(final byte[] L, final String pub) {
        return hash(concat(L, pub.getBytes()));
    }

    private Point computeXa(final byte[] L, final String pub) {
        byte[] a = aggregatedKeyHash(L, pub);
//        System.out.println("compute a: " + new BigInteger(a));
        BigInteger intA = toUnsignedBigInteger(a);
//        this.ai = intA.toString().getBytes();
        System.out.println("compute this.ai: " + intA);

        PublicKey publicKey = new PublicKey(pub);
        Point point = publicKey.getPoint();

        return point.scalarMultiply(intA);
    }

    private BigInteger toUnsignedBigInteger(byte[] a) {
        BigInteger intA = new BigInteger(a);
        if (intA.signum() == -1) {
            intA = intA.negate();
        }
        return intA;
    }

    /**
     *
     *
     * @return
     */
    public PublicKey computeAggPubKeys() {
        byte[] L = multisetOfPublicKeys(cosigners);

        Optional<Point> optPubKeys = cosigners.stream().map(pub -> computeXa(L, pub)).reduce((x, y) -> x.add(y));

        Point aggregatedPoints = optPubKeys.get();

        PublicKey aggregatedPubKeys = new PublicKey(aggregatedPoints);

        this.aggregatedPubKeys = aggregatedPubKeys;

        byte[] a = aggregatedKeyHash(L, this.privateKey.getPublicKey().getPublicKey());
        this.ai = a;

        return aggregatedPubKeys;
    }

    /**
     * Hash function commitmentHash is used in the commitment phase
     *
     * @param input
     * @return
     */
    public byte[] commitmentHash(byte[] input) {
        return  hash(input);
    }

    /*private byte[] comH(String publicKey) {
        return hash(publicKey.getBytes());
    }*/

    private byte[] multisetOfPublicKeys(List<String> pubKeys) {
        this.multisetL = pubKeys.stream().map(x -> BaseEncoding.base16().decode(x)).reduce((x, y) -> MyUtil.concat(x, y)).get();
        System.out.println("size of multiset " + this.multisetL.length);
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

        PublicKey rPublicKey = new PublicKey(pR);

        byte[] t = commitmentHash(rPublicKey.getPublicKey().getBytes());

        this.rCommitment = new RCommitment(this.privateKey.getPublicKey().getPublicKey(), rPublicKey.getPublicKey());

        return new TCommitment(this.privateKey.getPublicKey().getPublicKey(), t);
    }

    public PublicKey computeAggR() {

        Optional<Point> optR = this.rCommitments.stream()
                .map(x -> new PublicKey(x.getR()).getPoint())
                .reduce((x, y) -> x.add(y));

        Point aggR = optR.get();

        PublicKey publicKey = new PublicKey(aggR);

        this.aggR = publicKey;

        return publicKey;
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
        final String pR = rCommitment.getR();

        List<TCommitment> tcomm = this.tCommitments.stream().filter(x -> x.getPublicKey().equals(rCommitment.getPub())).collect(Collectors.toList());


        if (tcomm.size() == 1) {

            byte[] rh =  commitmentHash(pR.getBytes());

            if (Arrays.equals(tcomm.get(0).getT(), rh)) {
                this.rCommitments.add(rCommitment);
            }
        }
    }

    public void setCosigners(final List<String> pubKeys) {
        this.cosigners.addAll(pubKeys);
//        System.out.println(this.cosigners);
        this.cosigners.sort(Comparator.comparing(String::new));
        System.out.println(this.cosigners);
//        this.aggregatedPubKeys = computeAggPubKeys(cosigners);
    }

    public BigInteger sign(final byte[] m) {
//        Optional<Point> optR = this.rCommitments.stream().map(RCommitment::getR).reduce((x, y) -> x.add(y));
//        Point aggR = optR.get();

        String msg = new String(m);
        System.out.println("signing with m: " + msg);

        System.out.println("this.aggregatedPubKeys.toString(): " + this.aggregatedPubKeys.getPublicKey());
        System.out.println("this.aggR.toString(): " + this.aggR.getPublicKey());

        byte[] XR = concat(this.aggregatedPubKeys.getPublicKey().getBytes(), this.aggR.getPublicKey().getBytes());

        byte[] XRm = concat(XR, m);

        byte[] c = commitmentHash(XRm);

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

        Point right = new PublicKey(this.rCommitment.getR()).getPoint().add(caPublicKey);

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

        return new Signing(this.privateKey.getPublicKey().getPublicKey(), this.s);
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
            byte[] c = commitmentHash(XRm);

            BigInteger intC = toUnsignedBigInteger(c);
            System.out.println("receiveSig c: " + intC);


            byte[] a = aggregatedKeyHash(this.multisetL, sign.getPublicKey());

            BigInteger intA = toUnsignedBigInteger(a);

            System.out.println("receiveSig a: " + intA);

            List<RCommitment> rcomm = this.rCommitments.stream().filter(x -> x.getPub().equals(sign.getPublicKey())).collect(Collectors.toList());
            if (rcomm.size() == 1) {

                Point right = new PublicKey(rcomm.get(0).getR()).getPoint().add(
                        new PublicKey(sign.getPublicKey()).getPoint().scalarMultiply(intC).scalarMultiply(intA)
                );


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

        MultiSignatures signatures = new MultiSignatures(this.aggR.getPoint(), s);

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
        byte[] c = commitmentHash(XRm);

        BigInteger intC = toUnsignedBigInteger(c);
        System.out.println("verify c: " + intC);

        Point left = this.aggR.getPoint().add(this.aggregatedPubKeys.getPoint().scalarMultiply(intC));

        Point right = Secp256k1.G.scalarMultiply(this.signatures.getS());

        return left.equals(right);
    }
}
