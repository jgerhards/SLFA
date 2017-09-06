package com.rsyslog.slfa;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


public class PropertyReader {
	private InputStream inputStream;
	private String filename = "/home/jan/eclipse/projects/slfa/src/slfa/testconfig.properties";
 
	public String getPropValue(String propName) throws IOException {
		String result;
 
		try {
			Properties prop = new Properties();
 
			inputStream = new FileInputStream(filename);
 
			if (inputStream != null) {
				prop.load(inputStream);
			} else {
				throw new FileNotFoundException("property file '" + filename + "' not found");
			}
 
			// get the property value and print it out
			result = prop.getProperty(propName);

			return result;
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
