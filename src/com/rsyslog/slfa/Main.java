package com.rsyslog.slfa;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

	public static void main(String[] args) throws IOException {
		String configFile;

		Config config = new Config();

		configFile = System.getProperty("configfile");
		if(configFile == null) {
			configFile = System.getenv("LOGANONYMIZER_CONFIG");
		}
		if(configFile != null) {
			config.setFilename(configFile);
		}
		
		ArrayList<Type> typelist = config.getTypes();
		if(typelist == null) {
			return;
		}
		
		for(int i = 0; i < args.length; i++) {
			if(i > 0) {
				System.out.println();
				System.out.println();
			}
			LogFile current = new LogFile(args[i], typelist);
			current.anon();
		}
		
	}

}