package com.rsyslog.slfa.file;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Random;

import com.rsyslog.slfa.file.CurrMsg;
import com.rsyslog.slfa.types.Type;

/**
 * class to anonymize log files
 * @author Jan Gerhards
 *
 */
public class LogFile {
	private BufferedReader fileRd;
	private ArrayList<Type> list;
	private Random rand;
	
	
	/**
	 * default constructor for a LogFile
	 * @param path is the path to the log file
	 * @param typelist is a list of anonymization types
	 */
	public LogFile(String path, ArrayList<Type> typelist) {
		list = typelist;
		int listsize = list.size();
		for(int i = 0; i < listsize; i++) {
			list.get(i).onFileStart();
		}
		try {
			fileRd = new BufferedReader(new FileReader(path));
		} catch (FileNotFoundException e) {
			System.out.println("Exception: " + e);
		}
		rand = new Random(System.currentTimeMillis());
	}
	
	
	/**
	 * anonymizes the log file and prints the anonymized file to StdOut
	 */
	public void anon() {
		StringBuffer output = new StringBuffer();
		String msgIn = null;
		CurrMsg msg = new CurrMsg();
		int listsize = list.size();
		
		msg.setRand(rand);
		msg.setMsgOut(output);
		try {
			msgIn =  fileRd.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		while(msgIn != null) {	
			msg.setMsgIn(msgIn);
			msg.setCurrIdx(0);
			int msglen = msgIn.length();
			while(msg.getCurrIdx() < msglen) {
				msg.setNprocessed(0);
				for(int j = 0; j < listsize; j++) {
					list.get(j).anon(msg);
					if(msg.getNprocessed() > 0) {
						msg.setCurrIdx(msg.getCurrIdx() + msg.getNprocessed());
						break;
					}
				}
			}
			msg.endMsg();
			try {
				msgIn = fileRd.readLine();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			fileRd.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
