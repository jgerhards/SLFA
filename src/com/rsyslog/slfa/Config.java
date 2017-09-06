package com.rsyslog.slfa;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;

public class Config {
	private InputStream inputStream;
	private String filename = "/home/jan/eclipse/projects/slfa/src/slfa/testconfig.properties";
 
	private ArrayList<Type> readConfigFile(Properties prop) {
		ArrayList<Type> list = new ArrayList<Type>();
		String types = prop.getProperty("anonymizer");
		
		if(types.contains("ipv4")) {
			list.add(new IPv4_Type());
		}
		
		int listLen = list.size();
		for(int i = 0; i < listLen; i++) {
			list.get(i).getConfig(prop);
		}
		((IPv4_Type) list.get(0)).testtest();
		return list;
	}
	
	
	public ArrayList<Type> getTypes() throws IOException {
		Properties prop = null;
		try {
			prop = new Properties();
 
			inputStream = new FileInputStream(filename);
 
			if (inputStream != null) {
				prop.load(inputStream);
				return readConfigFile(prop);
			} else {
				throw new FileNotFoundException("property file '" + filename + "' not found");
			}
		} catch (Exception e) {
			System.out.println("Exception: " + e);
		} finally {
			inputStream.close();
		}
		return null;
	}
	
	public void setFilename(String name) {
		filename = name;
	}
}
