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


	/**
	 * moves every bit of the first value by 16 to the left
	 * and adds a value
	 * 
	 * @param toAdd is the value to add
	 */
	public void appendToHigh(int toAdd) {
		high = high << 16;
		high = high + toAdd;
	}

	
	/**
	 * moves every bit of the second value by 16 to the left
	 * and adds a value
	 * 
	 * @param toAdd is the value to add
	 */	
	public void appendToLow(int toAdd) {
		low = low << 16;
		low = low + toAdd;
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
