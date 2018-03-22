package com.rsyslog.slfa.preference;

import com.rsyslog.slfa.anonymization.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Properties;

/**
 * class to provide functions to get all anonymization anonymization
 *
 * @author Jan Gerhards
 */
public class Config {
    private InputStream inputStream;
    private String filepath = null;


    /**
     * reads a property and builds a list of all
     * anonymization anonymization named in the property
     *
     * @param prop is the property to read out of
     * @return an ArrayList of all anonymization anonymization
     */
    private ArrayList<Anonymizer> readConfigFile(Properties prop) {
        ArrayList<Anonymizer> list = new ArrayList<>();
        String types = prop.getProperty("anonymizer");
        String[] split = types.split(" ");
        int splitnum = split.length;

        for (int i = 0; i < splitnum; i++) {
            if (split[i].charAt(split[i].length() - 1) == ' ' || split[i].charAt(split[i].length() - 1) == ',') {
                split[i] = split[i].substring(0, split[i].length() - 1);
                if (split[i].charAt(split[i].length() - 1) == ',') {
                    split[i] = split[i].substring(0, split[i].length() - 1);
                }
            }
        }
        for (int i = 0; i < splitnum; i++) {
            switch (split[i]) {
                case "ipv4":
                    list.add(new Ipv4Anonymizer());
                    break;
                case "ipv6":
                    list.add(new Ipv6Anonymizer());
                    break;
                case "embeddedipv4":
                    list.add(new EmbeddedIpv4Anonymizer());
                    break;
                case "regex":
                    i++;
                    if (i < splitnum) {
                        int numreg = Math.max(Integer.parseInt(split[i]), 0);
                        list.add(new RegexAnonymizer(numreg));
                    } else {
                        System.err.println("error: last regexanonymizer must be assigned a number");
                    }
                    break;
                default:
                    System.err.println("error: unknown anonymization type '" + split[i] + "' ignored");
                    break;
            }
        }
        list.add(new NoneAnonymizer());

        for (Anonymizer aList : list) {
            aList.getConfig(prop);
        }
        return list;
    }


    /**
     * gets a list of anonymization anonymization from the preference file
     *
     * @return an ArrayList of anonymization anonymization
     * @throws IOException
     */
    public ArrayList<Anonymizer> getTypes() throws IOException {
        Properties prop;
        if (filepath == null) {
            System.err.println("preference error: no file specified as preference file, program will exit");
            return null;
        }
        try {
            prop = new Properties();
            inputStream = new FileInputStream(filepath);
            prop.load(inputStream);
            return readConfigFile(prop);
        } catch (Exception e) {
            System.err.println("Error opening configuration file (" + filepath + "), program will exit");
            return null;
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
        }
    }


    /**
     * sets the filepath for the configfile
     *
     * @param path is the path of the preference file
     */
    public void setFilepath(String path) {
        filepath = path;
    }
}
