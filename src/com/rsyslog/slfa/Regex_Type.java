package com.rsyslog.slfa;

import java.util.Properties;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Regex_Type extends Type{
	private enum anonmode {REPLACE, RANDOM};
	
	private boolean jumpover;  //if no regex is given, ignore type
	
	private int num;
	private int lastStart;
	private anonmode mode;
	private String replace;
	private boolean keepNum;
	private boolean keepChar;
	private boolean keepSpChar;
	Pattern match;
	int end;

	private void appendEnd(CurrMsg msg) {
		int regexLen = msg.getNprocessed();
		Random rand = msg.getRand();
		int idx = msg.getCurrIdx();
		char c;
		boolean kept;
		
		switch(mode) {
		case RANDOM :
			for(int i = 0; i < regexLen; i++) {
				kept = false;
				if(keepNum) {
					c = msg.getMsgIn().charAt(idx + i);
					if(c >= '0' && '9' >= c) {
						kept = true;
						msg.getMsgOut().append(c);
					}
				}
				if(keepChar) {
					c = msg.getMsgIn().charAt(idx + i);
					if(c >= 'a' && 'z' >= c) {
						kept = true;
						msg.getMsgOut().append(c);
					}
				}
				if(!kept) {
					if(keepSpChar) {
						msg.getMsgOut().append(msg.getMsgIn().charAt(idx + i));
						
					} else {
						msg.getMsgOut().append((char) (rand.nextInt((95)) + 32));						
					}
				}
			}
			break;
		case REPLACE:
			msg.getMsgOut().append(replace);
			break;
		}
	}
	
	private void real_anon(CurrMsg msg) {
		if(msg.getCurrIdx() == 0) {
			lastStart = -1;
		}
		Matcher m = match.matcher(msg.getMsgIn());
		if(lastStart < msg.getCurrIdx()) {
			if(m.find(msg.getCurrIdx())) {
				lastStart = m.start();
				end = m.end();
			}
		}
		if(lastStart > msg.getCurrIdx() || lastStart == -1) {
			return;
		} else if (lastStart == msg.getCurrIdx()){
			msg.setNprocessed(end - lastStart);
			appendEnd(msg);
		}
	}
	
	@Override
	public void anon(CurrMsg msg) {
		if(jumpover) {
			return;
		} else {
			real_anon(msg);
		}
	}

	@Override
	public void getConfig(Properties prop) {
		String var;
		
		var = prop.getProperty("regex[" + num + "].in");
		if(var != null) {
			match = Pattern.compile(var);
		} else {
			System.out.println("no regular expression (regex[NUMBER_OF_REGEX].in) configured for regex[" + num + "], will be ignored");
			jumpover = true;
		}

		var = prop.getProperty("regex[" + num + "].mode");
		if(var != null) {
			if(var.contentEquals("replace")) {
				mode = anonmode.REPLACE;
				var = prop.getProperty("regex[" + num + "].replace");
				if(var != null) {
					replace = var;
				}
			} else if(var.contentEquals("random")) {
				mode = anonmode.RANDOM;
				var = prop.getProperty("regex[" + num + "].keep");
				String[] split = var.split(" ");
				int splitnum = split.length;

				for(int i = 0; i < splitnum; i++) {
					char lastChar = split[i].charAt(split[i].length() - 1);
					while(lastChar == ',' || lastChar == ' ' || lastChar == ';') {
						split[i] = split[i].substring(0, split[i].length() - 1);
						split[i].trim();
						lastChar = split[i].charAt(split[i].length() - 1);
					}
					if(split[i].compareTo("num") == 0) {
						keepNum = true;
					}
					if(split[i].compareTo("char") == 0) {
						keepChar = true;
					}
					if(split[i].compareTo("spchar") == 0) {
						keepSpChar = true;
					}
				}
			}
		}
	}

	public Regex_Type(int name) {
		jumpover = false;
		num = name;
		mode = anonmode.RANDOM;
		keepNum = false;
		keepChar = false;
		keepSpChar = false;
	}
}
