package com.rsyslog.slfa;

import com.rsyslog.slfa.config.Config;
import com.rsyslog.slfa.file.LogFile;
import com.rsyslog.slfa.types.Type;

import java.io.IOException;
import java.util.ArrayList;

public class Main {

    public static void main(String[] args) throws IOException {
        String configFile;

        System.err.println("slfa version 1. Copyright 2017 Jan Gerhards");
        System.err.println("doc and more info: https://github.com/jgerhards/SLFA");
        Config config = new Config();

        configFile = System.getProperty("configfile");
        if (configFile == null) {
            configFile = System.getenv("LOGANONYMIZER_CONFIG");
        }
        if (configFile != null) {
            config.setFilepath(configFile);
        }

        ArrayList<Type> typelist = config.getTypes();
        if (typelist == null) {
            return;
        }

        for (int i = 0; i < args.length; i++) {
            if (i > 0) {
                System.out.println("\n\n");
            }
            LogFile current = new LogFile(args[i], typelist);
            current.anon();
        }
        if (System.getenv("LOGANONYMIZER_READ_FROM_STDIN") != null || System.getProperty("stdin") != null) {
            if (args.length > 0) {
                System.out.println("\n\n");
            }
            new LogFile(System.in, typelist).anon();
        }
    }

}
