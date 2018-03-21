package com.rsyslog.slfa.model;

import com.rsyslog.slfa.anonymization.Anonymizer;

import java.io.*;
import java.util.ArrayList;

/**
 * class to anonymize log files
 *
 * @author Jan Gerhards
 */
public class LogFile {
    private BufferedReader fileRd;
    private ArrayList<Anonymizer> list;

    /**
     * default constructor for a LogFile with an filepath as parameter
     *
     * @param path     is the path to the log file
     * @param typelist is a list of anonymization anonymization
     */
    public LogFile(String path, ArrayList<Anonymizer> typelist) {
        FileReader fr = null;
        try {
            fr = new FileReader(path);
        } catch (FileNotFoundException e) {
            System.err.println("Error: File not readable: " + path);
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
    public LogFile(InputStream input, ArrayList<Anonymizer> typelist) {
        InputStreamReader isr = new InputStreamReader(input);
        init(isr, typelist);
    }

    /**
     * Do init with params
     *
     * @param reader   reader to be set
     * @param typelist is a list of anonymization anonymization
     */
    private void init(InputStreamReader reader, ArrayList<Anonymizer> typelist) {
        list = typelist;
        fileRd = new BufferedReader(reader);
    }

    private String readLineFromInput() {
        try {
            return fileRd.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * anonymizes the log file and prints the anonymized file to StdOut
     */
    public void anon() {
        String line;
        LogMessage msg = new LogMessage();
        int listsize = list.size();

        while ((line = readLineFromInput()) != null) {
            msg.setInputMessage(line);
            int msglen = line.length();
            while (msg.getCurrentIndex() < msglen) {
                msg.setProcessedChars(0);
                for (int j = 0; j < listsize; j++) {
                    list.get(j).anonymize(msg);
                    if (msg.getProcessedChars() > 0) {
                        msg.setCurrentIndex(msg.getCurrentIndex() + msg.getProcessedChars());
                        break;
                    }
                }
            }
            msg.finishMessage();
        }
        try {
            if (fileRd != null) {
                fileRd.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
