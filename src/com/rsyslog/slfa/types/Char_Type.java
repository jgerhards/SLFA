package com.rsyslog.slfa.types;

import java.util.Properties;

import com.rsyslog.slfa.file.CurrMsg;

/**
 * anonymization type that is used when  no other type fits
 * @author Jan Gerhards
 *
 */
public class Char_Type extends Type {

	
	/**
	 * appends the next character of a message to its output buffer
	 * 
	 * @param msg is the message
	 */
	@Override
	public void anon(CurrMsg msg) {
		msg.getMsgOut().append(msg.getMsgIn().charAt(msg.getCurrIdx()));
		msg.setNprocessed(1);
	}

	/**
	 * empty, since no configuration is needed for this type
	 */
	@Override
	public void getConfig(Properties prop) {
		return;
	}

}
