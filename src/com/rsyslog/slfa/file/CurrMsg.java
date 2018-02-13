package com.rsyslog.slfa.file;

import java.util.Random;

/**
 * class to store the message that is currently worked on and additional information
 * @author Jan Gerhards
 *
 */
public class CurrMsg {
	private String msgIn;
	private StringBuffer msgOut;
	private int nprocessed;
	private int currIdx;
	private Random rand;
		
	/**
	 * getter for the message that is currently being processed
	 * @return the message
	 */
	public String getMsgIn() {
		return msgIn;
	}
	
	/**
	 * setter for the message being worked on
	 * @param msgIn is the new message
	 */
	public void setMsgIn(String msgIn) {
		this.msgIn = msgIn;
	}

	/**
	 * getter for the output buffer
	 * @return output buffer
	 */
	public StringBuffer getMsgOut() {
		return msgOut;
	}

	/**
	 * setter for the output buffer
	 * @param msgOut is the output buffer
	 */
	public void setMsgOut(StringBuffer msgOut) {
		this.msgOut = msgOut;
	}

	/**
	 * getter for the number of characters processed so far
	 * note: this refers to the character processed by an anonymization
	 * type, not the current index
	 * 
	 * @return the number of processed characters
	 */
	public int getNprocessed() {
		return nprocessed;
	}

	/**
	 * setter for the number of characters processed so far
	 * note: this refers to the character processed by an anonymization
	 * type, not the current index
	 * 
	 * @param nprocessed is the number of characters processed
	 */
	public void setNprocessed(int nprocessed) {
		this.nprocessed = nprocessed;
	}

	/**
	 * getter for the current index
	 * @return the current index
	 */
	public int getCurrIdx() {
		return currIdx;
	}

	/**
	 * setter for the current index
	 * 
	 * @param currIdx is the current index
	 */
	public void setCurrIdx(int currIdx) {
		this.currIdx = currIdx;
	}

	/**
	 * getter for the randomizer
	 * @return rand
	 */
	public Random getRand() {
		return rand;
	}

	/**
	 * setter for the randomizer
	 * 
	 * @param rand is the randomizer
	 */
	public void setRand(Random rand) {
		this.rand = rand;
	}

	
	/**
	 * prints the anonymized message on StdOut and deletes the output buffer
	 */
	public void endMsg() {
		System.out.println(msgOut);
		msgOut.delete(0, msgOut.length());
	}
}
