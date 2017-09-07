package com.rsyslog.slfa;

import java.util.Random;

public class CurrMsg {
	private String msgIn;
	private StringBuffer msgOut;
	private int nprocessed;
	private int currIdx;
	private Random rand;
		
	public String getMsgIn() {
		return msgIn;
	}
	
	public void setMsgIn(String msgIn) {
		this.msgIn = msgIn;
	}

	public StringBuffer getMsgOut() {
		return msgOut;
	}

	public void setMsgOut(StringBuffer msgOut) {
		this.msgOut = msgOut;
	}

	public int getNprocessed() {
		return nprocessed;
	}

	public void setNprocessed(int nprocessed) {
		this.nprocessed = nprocessed;
	}

	public int getCurrIdx() {
		return currIdx;
	}

	public void setCurrIdx(int currIdx) {
		this.currIdx = currIdx;
	}

	public Random getRand() {
		return rand;
	}

	public void setRand(Random rand) {
		this.rand = rand;
	}

	public void endMsg() {
		System.out.println(msgOut);
		msgOut.delete(0, msgOut.length());
	}
}
