package com.tiennv.ec;

public class RCommitment {
    private final Point pub;
    private final Point pR;


    public RCommitment(Point pub, Point pR) {
        this.pub = pub;
        this.pR = pR;
    }

    public Point getPub() {
        return pub;
    }

    public Point getR() {
        return pR;
    }
}
