package com.rsyslog.slfa.model;

import com.rsyslog.slfa.anonymization.AnonType;

import java.io.*;
import java.util.ArrayList;
import java.util.Random;

/**
 * class to anonymize log files
 *
 * @author Jan Gerhards
 */
public class LogFile {
    private BufferedReader fileRd;
    private ArrayList<AnonType> list;
    private Random rand;

    /**
     * default constructor for a LogFile with an filepath as parameter
     *
     * @param path     is the path to the log file
     * @param typelist is a list of anonymization anonymization
     */
    public LogFile(String path, ArrayList<AnonType> typelist) {
        FileReader fr = null;
        try {
            fr = new FileReader(path);
        } catch (FileNotFoundException e) {
            System.out.println("Error: File not readable: " + path);
            System.exit(1);
        }
        init(fr, typelist);
    }

    /**
     * Constructor for a LogFile with an InputStream
     *
     * @param input    an InputStream
     * @param typelist is a list of anonymization anonymization
     */
    public LogFile(InputStream input, ArrayList<AnonType> typelist) {
        InputStreamReader isr = new InputStreamReader(input);
        init(isr, typelist);
    }

    /**
     * Do init with params
     *
     * @param reader   reader to be set
     * @param typelist is a list of anonymization anonymization
     */
    private void init(InputStreamReader reader, ArrayList<AnonType> typelist) {
        list = typelist;
        int listsize = list.size();
        for (int i = 0; i < listsize; i++) {
            list.get(i).onFileStart();
        }
        fileRd = new BufferedReader(reader);
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
            msgIn = fileRd.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        while (msgIn != null) {
            msg.setMsgIn(msgIn);
            msg.setCurrIdx(0);
            int msglen = msgIn.length();
            while (msg.getCurrIdx() < msglen) {
                msg.setNprocessed(0);
                for (int j = 0; j < listsize; j++) {
                    list.get(j).anon(msg);
                    if (msg.getNprocessed() > 0) {
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