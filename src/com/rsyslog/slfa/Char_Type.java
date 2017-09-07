package com.rsyslog.slfa;

import java.util.Properties;

public class Char_Type extends Type {

	@Override
	public void anon(CurrMsg msg) {
		msg.getMsgOut().append(msg.getMsgIn().charAt(msg.getCurrIdx()));
		msg.setNprocessed(1);
	}

	@Override
	public void getConfig(Properties prop) {
		return;
	}

}
