package com.rsyslog.slfa.types;

/**
 * class consisting of two long values to save IPv6 address
 * @author Jan Gerhards
 *
 */
public class IPv6_Int {
	private long high;
	private long low;

	
	/**
	 * getter for first long value
	 * 
	 * @return first long value
	 */
	public long getHigh() {
		return high;
	}
	
	
	/**
	 * setter for first long value
	 * 
	 * @param high is the first long value
	 */
	public void setHigh(long high) {
		this.high = high;
	}

	
	/**
	 * getter for second long value
	 * 
	 * @return second long value
	 */
	public long getLow() {
		return low;
	}

	
	/**
	 * setter for second long value
	 * 
	 * @param high is the second long value
	 */
	public void setLow(long low) {
		this.low = low;
	}

   public boolean equals(Object cmp) {
		if(this.getHigh() == ((IPv6_Int)cmp).getHigh() && this.getLow() == ((IPv6_Int)cmp).getLow()) {
			return true;
		} else {
			return false;
		}
	}
	
	@Override
	public int hashCode() {
		return (int) ((high & 0xFFC00000) | (low & 0x3FFFFF));
	}
}
