package com.rsyslog.slfa.model;

import com.rsyslog.slfa.anonymization.Anonymizer;

import java.io.*;
import java.util.ArrayList;

/**
 * Anonymize log entries by given filepath or inputstream
 *
 * @author Jan Gerhards
 */
public class LogFile {
    private BufferedReader _inputReader;
    private ArrayList<Anonymizer> _anonymizers;

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
        _anonymizers = typelist;
        _inputReader = new BufferedReader(reader);
    }

    private String readLineFromInput() {
        try {
            return _inputReader.readLine();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * anonymizes the log file and prints the anonymized file to StdOut
     */
    public void anonymize() {
        LogMessage msg = new LogMessage();

        String line;
        while ((line = readLineFromInput()) != null) {
            msg.setInputMessage(line);
            int msglen = line.length();
            while (msg.getCurrentIndex() < msglen) {
                msg.setProcessedChars(0);
                for (Anonymizer anonymizer : _anonymizers) {
                    anonymizer.anonymize(msg);
                    if (msg.getProcessedChars() > 0) {
                        msg.setCurrentIndex(msg.getCurrentIndex() + msg.getProcessedChars());
                        break;
                    }
                }
            }
            msg.popPrintAnonymizedBuffer();
        }
        try {
            if (_inputReader != null) {
                _inputReader.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
