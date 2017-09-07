package com.rsyslog.slfa;

import java.util.Properties;

public abstract class Type {

	public void onFileStart() {
		return;
	}
	
	public void onFileEnd() {
		return;
	}
	
	public abstract void anon(CurrMsg msg);

	public abstract void getConfig(Properties prop);
}
