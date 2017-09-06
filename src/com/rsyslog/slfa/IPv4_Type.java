package com.rsyslog.slfa;

import java.util.Properties;

public class IPv4_Type extends Type {

	private enum mode {ZERO, RANDOM};
	private mode mode;
	private Boolean cons = false;
	private int bits;

	
	@Override
	public int anon(String msg) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void getConfig(Properties prop) {
		String var;
		
		var = prop.getProperty("ipv4.bits");
		if(var != null) {
			bits = Integer.parseInt(var);
		} else {
			bits = 16;
		}
		
		var = prop.getProperty("ipv4.mode");
		if(var.contentEquals("zero")) {
			mode = mode.ZERO;
		} else if(var.contentEquals("random")) {
			mode = mode.RANDOM;
		} else if(var.contentEquals("random-consistent")) {
			mode = mode.RANDOM;
			cons = true;
		}
	}
	
	public void testtest() {
		System.out.println("test: " + mode + " " + cons + " " + bits);
	}

}
