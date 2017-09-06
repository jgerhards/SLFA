package com.rsyslog.slfa;

import java.io.IOException;

public class Main {

	public static void main(String[] args) throws IOException {
		String configFile;

		Config config = new Config();

		configFile = System.getProperty("configfile");
		if(configFile != null) {
			config.setFilename(configFile);
		}
		
		System.out.println("test: " + System.getProperty("test") + "     file: " + configFile);
		
		config.getTypes();
		
		for(int i = 0; i < args.length; i++) {
			System.out.println("arg " + i + ": " + args[i]);
		}
		
	}

}