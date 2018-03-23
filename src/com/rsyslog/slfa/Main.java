package com.rsyslog.slfa;

import com.rsyslog.slfa.anonymization.Anonymizer;
import com.rsyslog.slfa.model.LogFile;
import com.rsyslog.slfa.preference.Config;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        boolean stdinInput = System.getenv("LOGANONYMIZER_READ_FROM_STDIN") != null || System.getProperty("stdin") != null;
        String configFile;

        // Exit if no arguments given and input not coming from stdin
        if (args.length == 0 && !stdinInput) {
            System.out.println("slfa version 1. Copyright 2017 Jan Gerhards");
            System.out.println("doc and more info: https://github.com/jgerhards/SLFA");
            System.exit(1);
        }
        Config config = new Config();

        configFile = System.getProperty("configfile");
        if (configFile == null) {
            configFile = System.getenv("LOGANONYMIZER_CONFIG");
        }
        if (configFile != null) {
            config.setFilepath(configFile);
        }

        ArrayList<Anonymizer> typelist = config.getTypes();
        if (typelist == null) {
            return;
        }

        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                System.out.println("\n\n");
            }
            LogFile current = new LogFile(args[i], typelist);
            current.anonymize();
        }
        if (stdinInput) {
            if (args.length > 0) {
                System.out.println("\n\n");
            }
            new LogFile(System.in, typelist).anonymize();
        }
    }

}
