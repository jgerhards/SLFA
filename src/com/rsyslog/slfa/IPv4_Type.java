package com.rsyslog.slfa;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;

public class IPv4_Type extends Type {

	private enum ipv4mode {ZERO, RANDOM};
	private ipv4mode mode;
	private boolean cons;
	private int bits;
	Hashtable<Integer, Integer> hash;
	
	private int[] ipParts;

	private int getposint(CurrMsg msg, int i, int j) {
		ipParts[i] = -1;
		while(j < msg.getMsgIn().length()) {
			char c = msg.getMsgIn().charAt(j);
			if('0' <= c && c <= '9') {
				if(ipParts[i] == -1) {
					ipParts[i] = 0;
				}
				ipParts[i] = ipParts[i] * 10 + (c - '0');
			} else {
				break;
			}
			j++;
		}
		return j;

	}
	
	private Boolean syntax(CurrMsg msg) {
		Boolean isIP = false;
		int i = msg.getCurrIdx();
		int msglen = msg.getMsgIn().length();

		i = getposint(msg, 0, i);
		if(ipParts[0] < 0 || ipParts[0] > 255) {
			return isIP;
		}
		if(i >= msglen || msg.getMsgIn().charAt(i) != '.') {
			return isIP;
		}
		i++;
		
		i = getposint(msg, 1, i);
		if(ipParts[1] < 0 || ipParts[1] > 255) {
			return isIP;
		}
		if(i >= msglen || msg.getMsgIn().charAt(i) != '.') {
			return isIP;
		}
		i++;
		
		i = getposint(msg, 2, i);
		if(ipParts[2] < 0 || ipParts[2] > 255) {
			return isIP;
		}
		if(i >= msglen || msg.getMsgIn().charAt(i) != '.') {
			return isIP;
		}
		i++;

		i = getposint(msg, 3, i);
		if(ipParts[3] < 0 || ipParts[3] > 255) {
			return isIP;
		}
		
		msg.setNprocessed(i - msg.getCurrIdx());
		isIP = true;
		return isIP;
	}
	
	private int ip2num() {
		int num = 0;
		
		for(int i = 0; i < 4; i++) {
			num <<= 8;
			num |= ipParts[i];
		}
		return num;
	}
	
	private int codeInt(int num, Random rand) {
		int randomNum = 0;
		
		if(bits == 32) {
			num = 0;
		} else {
			num = (num>>>bits)<<bits;
		}
		switch(mode) {
		case ZERO:
			break;
		case RANDOM:
			if(bits == 32) {
				randomNum = rand.nextInt();
			} else {
				randomNum = rand.nextInt() & ((1<<bits) - 1);
			}
			num = num | randomNum;
		default:
			break;
		}
		return num;
	}
	
	private void appendIP(int num, CurrMsg msg) {
		int parts[] = new int[4];
		
		for(int i = 3; i >= 0; i--) {
			parts[i] = num & 255;
			num >>>= 8;
		}
		for(int i = 0; i < 3; i++) {
			msg.getMsgOut().append(parts[i]);
			msg.getMsgOut().append('.');
			num >>>= 8;
		}
		msg.getMsgOut().append(parts[3]);
	}

	private void findIP(int num, CurrMsg msg) {
		Integer ip = (Integer) hash.get(num);
		if(ip == null) {
			ip = codeInt(num, msg.getRand());
			hash.put(num, ip);
		}
		appendIP(ip, msg);
	}
	
	@Override
	public void anon(CurrMsg msg) {
		int intAddress;
		
		if(syntax(msg)) {
			intAddress = ip2num();
			if(cons) {
				findIP(intAddress, msg);
			} else {
				intAddress = codeInt(intAddress, msg.getRand());
				appendIP(intAddress, msg);
			}
		}
	}

	public IPv4_Type() {
		ipParts = new int[4];
		bits = 16;
		mode = ipv4mode.ZERO;
		cons = false;
	}
	
	@Override
	public void getConfig(Properties prop) {
		String var;
		
		var = prop.getProperty("ipv4.bits");
		if(var != null) {
			bits = Integer.parseInt(var);
		}
		
		if(bits < 1 || bits > 32) {
			System.out.println("config error: invalid number of ipv4.bits (" + bits + "), corrected to 32");
			bits = 32;
		}
		
		var = prop.getProperty("ipv4.mode");
		if(var != null) {
			if(var.contentEquals("zero")) {
				mode = ipv4mode.ZERO;
			} else if(var.contentEquals("random")) {
				mode = ipv4mode.RANDOM;
			} else if(var.contentEquals("random-consistent")) {
				mode = ipv4mode.RANDOM;
				cons = true;
			}
		}

		if(cons) {
			hash = new Hashtable<Integer, Integer>();
		}
	}

}
