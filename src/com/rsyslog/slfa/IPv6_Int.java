package com.rsyslog.slfa;

public class IPv6_Int {
	private long high;
	private long low;

	public long getHigh() {
		return high;
	}
	public void setHigh(long high) {
		this.high = high;
	}

	public long getLow() {
		return low;
	}
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
