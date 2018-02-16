package com.rsyslog.slfa.types;

import java.util.Properties;

import com.rsyslog.slfa.file.CurrMsg;

/**
 * abstract class for all anonymization types
 * @author jan
 *
 */
public abstract class Type {

	/**
	 * function to call for every type before a new file is processed
	 */
	public void onFileStart() {
		return;
	}
	
	/**
	 * function to call for every type after a file has been processsed
	 */
	public void onFileEnd() {
		return;
	}
	
	/**
	 * anonymizes the message if it matches the anonymization type
	 * starting at the index and adds the anonymized part to msgOut
	 */
	public abstract void anon(CurrMsg msg);

	/**
	 * reads the parameters for the type out of the config file
	 * @param prop is the property to read out of
	 */
	public abstract void getConfig(Properties prop);
}
