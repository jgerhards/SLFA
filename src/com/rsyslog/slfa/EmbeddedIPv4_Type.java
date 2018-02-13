package com.rsyslog.slfa;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;


class EmbeddedIPv4_Type extends Type{
	private enum anonmode {ZERO, RANDOM};
	private anonmode mode;
	private boolean cons;
	private int bits;
	
	Hashtable<IPv6_Int, IPv6_Int> hash;
	private int[] ipParts;
	private int v4Start;
	private int v4Len;
	
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
	

	private int getHexVal(char c) {
		if('0' <= c && c <= '9') {
			return c - '0';
		} else if('a' <= c && c <= 'f') {
			return (c - 'a') + 10;
		} else if('A' <= c && c <= 'F') {
			return (c - 'A') + 10;
		} else {
			return -1;
		}
	}


	private Boolean syntaxV4(CurrMsg msg) {
		ipParts = new int[4];

		Boolean isIP = false;
		int oldIdx = v4Start;
		int i = oldIdx;
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
		
		v4Len = (i - oldIdx);
		isIP = true;
		return isIP;
	}

	private int validHexVal(CurrMsg msg) { //please note: this is a similar function to the one in IPv6_Type, but not the same
		int buflen = msg.getMsgIn().length();
		int idx =  msg.getCurrIdx() + msg.getNprocessed();
		int cyc = 0;

		while(idx < buflen) {
			switch(msg.getMsgIn().charAt(idx)) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':

			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':

			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
				cyc++;
				msg.addNprocessed(1);
				if(cyc == 5) {
					return 0;
				}
				break;
			case '.':
				if(cyc == 0) {
					msg.addNprocessed(1);
					return -2;					
				}
			case ':':
				if(cyc == 0) {
					msg.addNprocessed(1);
					return -1;
				}
				return cyc;
			default:
				return cyc;
			}
			idx++;
		}
		return cyc;
	}
	
	private int findV4Start(CurrMsg msg, int dotPos) {
		while(dotPos > 0) {
			if(msg.getMsgIn().charAt(dotPos) == ':') {
				return dotPos + 1;
			}
			dotPos--;
		}
		return -1; //should not happen
	}

	
	private IPv6_Int ip2int(CurrMsg msg) {
		IPv6_Int ip = new IPv6_Int();
		int num[] = {0, 0, 0, 0, 0, 0};
		int cyc = 0;
		int dots = 0;
		int val;
		int i;
		int iplen = msg.getNprocessed();

		for(i = msg.getCurrIdx(); i < v4Start && dots < 2; i++) {
			val = getHexVal(msg.getMsgIn().charAt(i));
			if(val == -1) {
				dots++;
				if(dots < 2) {
					cyc++;
				}
			} else {
				num[cyc] = num[cyc] * 16 + val;
				dots = 0;
			}
		}
		if(dots == 2) {
			if(i < v4Start - 1) {
				int shift = 0;
				cyc = 5;
				for(int j = v4Start - 1; j >= i; j--) {
					val = getHexVal(msg.getMsgIn().charAt(j));
					if(val == -1) {
						cyc--;
						shift = 0;
					} else {
						val <<= shift;
						shift += 4;
						num[cyc] += val;
					}
				}
			} else {
				while(cyc < 6) {
					num[cyc] = 0;
					cyc++;
				}
			}
		}

		for(i = 0; i < 4; i++) {
			ip.appendToHigh(num[i]);
		}
		while(i < 6) {
			ip.appendToLow(num[i]);
			i++;
		}
		ip.appendToLow(ipParts[0] << 8 | ipParts[1]);
		ip.appendToLow(ipParts[2] << 8 | ipParts[3]);

		return ip;

	}
	
	
	private void	code_ipv6_int(IPv6_Int ip, CurrMsg msg)
	{
		Random rand = msg.getRand();
		int bitscpy = bits;

		if(bitscpy == 128) { //has to be handled separately, since shift
							 //128 bits doesn't work on unsigned long long
			ip.setHigh(0);
			ip.setLow(0);
		} else if(bitscpy > 64) {
			ip.setLow(0);
			ip.setHigh((ip.getHigh() >>> (bitscpy - 64)) <<  (bitscpy - 64));
		} else if(bitscpy == 64) {
			ip.setLow(0);			
		} else {
			ip.setLow((ip.getLow() >>> bitscpy) <<  bitscpy);
		}
		switch(mode) {
		case ZERO:
			break;
		case RANDOM:
			if(bitscpy == 128) {
				ip.setHigh(rand.nextLong());
				ip.setLow(rand.nextLong());
			} else if(bitscpy > 64) {
				ip.setLow(rand.nextLong());
				ip.setHigh(ip.getHigh() | (rand.nextLong() & ((1l << (bitscpy - 64)) - 1)));
			} else if(bitscpy == 64) {
				ip.setLow(rand.nextLong());
			} else {
				ip.setLow(ip.getLow() | (rand.nextLong() & ((1l << bitscpy) - 1)));
			}
			break;
		default:
			System.out.println("error: unexpected code reached");
		}
	}


	private void appendv4(int num, CurrMsg msg) {
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


	private void appendIP(IPv6_Int ip, CurrMsg msg) {
		int num[] = new int[8];
		int i;
		IPv6_Int ipcpy;
		
		if(cons) {
			ipcpy = new IPv6_Int();
			ipcpy.setHigh(ip.getHigh());
			ipcpy.setLow(ip.getLow());
		} else {
			ipcpy = ip;
		}

		for(i = 7; i > 3; i--) {
			num[i] = (int) (ipcpy.getLow() & 0xffff);
			ipcpy.setLow(ipcpy.getLow() >>> 16);
		}
		while(i > -1) {
			num[i] = (int) (ipcpy.getHigh() & 0xffff);
			ipcpy.setHigh(ipcpy.getHigh() >>> 16);
			i--;
		}

		for(int j = 0; j < 6; j++) {
			msg.getMsgOut().append(Integer.toHexString(num[j]));
			msg.getMsgOut().append(':');
		}
		
		appendv4((num[6] << 8) | num[7], msg);
	}

	
	private Boolean syntax(CurrMsg msg) {
		Boolean lastSep = false;
		Boolean hadAbbrev = false;
		int ipParts = 0;
		int numLen;
		int buflen = msg.getMsgIn().length();

		while(msg.getNprocessed() < buflen) {
			numLen = validHexVal(msg);
			if(numLen > 0) {  //found a valid num
				if((ipParts == 6 && hadAbbrev) || ipParts > 6) { /*has to be 6 since first part of IPv4
																is also a valid hash num*/
					return false;
				}
				if (ipParts == 0 && lastSep && !hadAbbrev) {
					return false;
				}
				lastSep = false;
				ipParts++;
			} else if (numLen == -1) {  //':'
				if(lastSep) {
					if(hadAbbrev) {
						return false;
					} else {
						hadAbbrev = true;
					}
				}
				lastSep = true;
			} else if (numLen == -2) {  //'.'
				if (lastSep || (ipParts == 0 && hadAbbrev) || (ipParts <= 6 && !hadAbbrev)) {
					return false;
				}
				v4Start = findV4Start(msg, msg.getNprocessed() - 1);
				if(syntaxV4(msg)) {
					msg.addNprocessed(v4Len - (msg.getNprocessed() - v4Start));
					return true;
				} else {
					return false;
				}
			} else {  //no valid num
				return false;
			}
		}

		return false;
	}

	
	private void findIP(CurrMsg msg, IPv6_Int num) {
		IPv6_Int ip = hash.get(num);
		if(ip == null) {
			ip = new IPv6_Int();
			ip.setHigh(num.getHigh());
			ip.setLow(num.getLow());
			code_ipv6_int(ip, msg);
			hash.put(num, ip);
		}
		appendIP(ip, msg);
	}
	

	@Override
	public void anon(CurrMsg msg) {
		v4Len = 0;
		v4Start = 0;
		if(syntax(msg)) {
			IPv6_Int ip = ip2int(msg);
			if(cons) {
				findIP(msg, ip);
			} else {
				code_ipv6_int(ip, msg);
				appendIP(ip, msg);
			}
//System.out.println("found embedded: \"" + msg.getMsgIn().substring(msg.getCurrIdx()) + "\"");
//msg.setNprocessed(0);
		} else {
			msg.setNprocessed(0);
		}
	}

	@Override
	public void getConfig(Properties prop) {
		String var;
		
		var = prop.getProperty("embeddedipv4.bits");
		if(var != null) {
			bits = Integer.parseInt(var);
		}
		
		if(bits < 1 || bits > 128) {
			System.out.println("config error: invalid number of ipv4.bits (" + bits + "), corrected to 128");
			bits = 128;
		}
		
		var = prop.getProperty("embeddedipv4.mode");
		if(var != null) {
			if(var.contentEquals("zero")) {
				mode = anonmode.ZERO;
			} else if(var.contentEquals("random")) {
				mode = anonmode.RANDOM;
			} else if(var.contentEquals("random-consistent")) {
				mode = anonmode.RANDOM;
				cons = true;
			}
		}
		
		if(cons) {
			hash = new Hashtable<IPv6_Int, IPv6_Int>();
		}
	}
	
	
	public EmbeddedIPv4_Type() {
		v4Len = 0;
		v4Start = 0;
		bits = 96;
		mode = anonmode.ZERO;
		cons = false;
	}

}
