package com.rsyslog.slfa;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;

public class Config {
	private InputStream inputStream;
	private String filename = null;
 
	private ArrayList<Type> readConfigFile(Properties prop) {
		ArrayList<Type> list = new ArrayList<Type>();
		String types = prop.getProperty("anonymizer");
		String[] split = types.split(" ");
		int splitnum = split.length;
		
		for(int i = 0; i < splitnum; i ++) {
			if(split[i].charAt(split[i].length() - 1) == ' ' || split[i].charAt(split[i].length() - 1) == ',') {
				split[i] = split[i].substring(0, split[i].length() - 1);
				if(split[i].charAt(split[i].length() - 1) == ',') {
					split[i] = split[i].substring(0, split[i].length() - 1);
				}
			}
		}
		for(int i = 0; i < splitnum; i ++) {
			if(split[i].equals("ipv4")) {
				list.add(new IPv4_Type());
			} else if(split[i].equals("ipv6")) {
				list.add(new IPv6_Type());
			} else if(split[i].equals("embeddedipv4")) {
				list.add(new EmbeddedIPv4_Type());
			} else if(split[i].equals("regex")) {
				i++;
				int numreg = Integer.parseUnsignedInt(split[i]);
				list.add(new Regex_Type(numreg));
			} else {
				System.out.println("error: unknown anonymization type '" + split[i] + "' ignored");
			}
		}
		list.add(new Char_Type());
		
		int listLen = list.size();
		for(int i = 0; i < listLen; i++) {
			list.get(i).getConfig(prop);
		}
		return list;
	}

	
	public ArrayList<Type> getTypes() throws IOException {
		Properties prop = null;
		if(filename == null) {
			System.out.println("config error: no file specified as config file, program will exit");
			return null;
		}
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
			System.out.println("Error opening configuration file (" + filename + "), program will exit");
			return null;
		} finally {
			if(inputStream != null) {
				inputStream.close();
			}
		}
	}
	
	public void setFilename(String name) {
		filename = name;
	}
}
