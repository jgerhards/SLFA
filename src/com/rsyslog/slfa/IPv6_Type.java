package com.rsyslog.slfa;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;


public class IPv6_Type extends Type {
	
	private enum anonmode {ZERO, RANDOM};
	private anonmode mode;
	private boolean cons;
	private int bits;
	Hashtable<IPv6_Int, IPv6_Int> hash;

	private int validHexVal(CurrMsg msg) {
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
				msg.setNprocessed(msg.getNprocessed() + 1);
				if(cyc == 5) {
					return 0;
				}
				break;
			case ':':
				if(cyc == 0) {
					msg.setNprocessed(msg.getNprocessed() + 1);
					return -1;
				}  //no break so it return cyc if cyc != 0
			default:
				return cyc;
			}
			idx++;
		}
		return cyc;
	}
	
	private Boolean syntax(CurrMsg msg) {
		Boolean lastSep = false;
		Boolean hadAbbrev = false;
		Boolean lastAbbrev = false;
		int ipParts = 0;
		int numLen;
		int buflen = msg.getMsgIn().length();

		while(msg.getNprocessed() < buflen) {
			numLen = validHexVal(msg);
			if(numLen > 0) {  //found a valid num
				if((ipParts == 7 && hadAbbrev) || ipParts > 7) {
					return false;
				}
				if (ipParts == 0 && lastSep && !hadAbbrev) {
					return false;
				}
				lastSep = false;
				lastAbbrev = false;
				ipParts++;
			} else if (numLen < 0) {  //':'
				if(lastSep) {
					if(hadAbbrev) {
						return false;
					} else {
						hadAbbrev = true;
						lastAbbrev = true;
					}
				}
				lastSep = true;
			} else {  //no valid num
				if(lastSep) {
					if(lastAbbrev && ipParts < 8) {
						return true;
					}
					return false;
				}
				if((ipParts == 8 && !hadAbbrev) || (ipParts < 8 && hadAbbrev)) {
					return true;
				} else {
					return false;
				}
			}
		}

		if((!lastSep && (ipParts == 8 && !hadAbbrev)) || (ipParts < 8 && hadAbbrev)) {
			return true;
		} else {
			return false;
		}
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

	private IPv6_Int ip2int(CurrMsg msg) {
		IPv6_Int ip = new IPv6_Int();
		int num[] = {0, 0, 0, 0, 0, 0, 0, 0};
		int cyc = 0;
		int dots = 0;
		int val;
		int i;
		int iplen = msg.getNprocessed();

		int endIP = msg.getCurrIdx() + iplen;
		for(i = msg.getCurrIdx(); i < endIP && dots < 2; i++) {
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
			if(i < iplen - 1) {
				int shift = 0;
				cyc = 7;
				for(int j = iplen - 1; j >= i; j--) {
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
				while(cyc < 8) {
					num[cyc] = 0;
					cyc++;
				}
			}
		}

		for(i = 0; i < 4; i++) {
			ip.setHigh(ip.getHigh() << 16);
			ip.setHigh(ip.getHigh() | num[i]);
		}
		while(i < 8) {
			ip.setLow(ip.getLow() << 16);
			ip.setLow(ip.getLow() | num[i]);
			i++;
		}

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

		for(int j = 0; j < 7; j++) {
			msg.getMsgOut().append(Integer.toHexString(num[j]));
			msg.getMsgOut().append(':');
		}
		msg.getMsgOut().append(Integer.toHexString(num[7]));

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
		if(syntax(msg)) {
			IPv6_Int ip = ip2int(msg);
			if(cons) {
				findIP(msg, ip);
			} else {
				code_ipv6_int(ip, msg);
				appendIP(ip, msg);
			}
		} else {
			msg.setNprocessed(0);
		}
	}

	@Override
	public void getConfig(Properties prop) {
		String var;
		
		var = prop.getProperty("ipv6.bits");
		if(var != null) {
			bits = Integer.parseInt(var);
		}
		
		if(bits < 1 || bits > 128) {
			System.out.println("config error: invalid number of ipv4.bits (" + bits + "), corrected to 128");
			bits = 128;
		}
		
		var = prop.getProperty("ipv6.mode");
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

	public IPv6_Type() {
		bits = 96;
		mode = anonmode.ZERO;
		cons = false;
	}

}
