package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.LogMessage;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;

/**
 * Type to anonymize IPv4 addresses
 *
 * @author Jan Gerhards
 */
public class Ipv4Anonymizer implements Anonymizer {

    private enum ipv4mode {ZERO, RANDOM}

    ;
    private ipv4mode mode;
    private boolean cons;
    private int bits;
    Hashtable<Integer, Integer> hash;

    private int[] ipParts;


    /**
     * reads a message from a starting position and checks, if it starts with an integer. If it
     * does, writes the integer into ipParts, else sets a value in ipParts to -1.
     *
     * @param msg the message to read
     * @param i   the position in ipParts
     * @param j   the position to start reading the message
     * @return the starting position with the length of the integer added
     */
    private int getposint(LogMessage msg, int i, int j) {
        ipParts[i] = -1;
        while (j < msg.getInputMessage().length()) {
            char c = msg.getInputMessage().charAt(j);
            if ('0' <= c && c <= '9') {
                if (ipParts[i] == -1) {
                    ipParts[i] = 0;
                }
                ipParts[i] = ipParts[i] * 10 + (c - '0');
            } else {
                break;
            }
            j++;
        }
        return j;

    }


    /**
     * checks if the message contains an IPv4 address at the current index.
     *
     * @param msg is the messgae to check
     * @return true if is contains an IPv4 address at the current index, else false
     */
    private Boolean syntax(LogMessage msg) {
        Boolean isIP = false;
        int i = msg.getCurrentIndex();
        int msglen = msg.getInputMessage().length();

        i = getposint(msg, 0, i);
        if (ipParts[0] < 0 || ipParts[0] > 255) {
            return isIP;
        }
        if (i >= msglen || msg.getInputMessage().charAt(i) != '.') {
            return isIP;
        }
        i++;

        i = getposint(msg, 1, i);
        if (ipParts[1] < 0 || ipParts[1] > 255) {
            return isIP;
        }
        if (i >= msglen || msg.getInputMessage().charAt(i) != '.') {
            return isIP;
        }
        i++;

        i = getposint(msg, 2, i);
        if (ipParts[2] < 0 || ipParts[2] > 255) {
            return isIP;
        }
        if (i >= msglen || msg.getInputMessage().charAt(i) != '.') {
            return isIP;
        }
        i++;

        i = getposint(msg, 3, i);
        if (ipParts[3] < 0 || ipParts[3] > 255) {
            return isIP;
        }

        msg.setProcessedChars(i - msg.getCurrentIndex());
        isIP = true;
        return isIP;
    }


    /**
     * converts the ip address stored in ipParts to an integer
     *
     * @return the ip as an integer
     */
    private int ip2num() {
        int num = 0;

        for (int i = 0; i < 4; i++) {
            num <<= 8;
            num |= ipParts[i];
        }
        return num;
    }


    /**
     * anonymizes an ip address
     *
     * @param num  is the address to anonymize as an integer
     * @param rand is the randomizer
     * @return the anonymized address as an integer
     */
    private int codeInt(int num, Random rand) {
        int randomNum = 0;

        if (bits == 32) {
            num = 0;
        } else {
            num = (num >>> bits) << bits;
        }
        switch (mode) {
            case ZERO:
                break;
            case RANDOM:
                if (bits == 32) {
                    randomNum = rand.nextInt();
                } else {
                    randomNum = rand.nextInt() & ((1 << bits) - 1);
                }
                num = num | randomNum;
            default:
                break;
        }
        return num;
    }


    /**
     * converts an integer to an equivalent IPv4 address and appends
     * that to the message output buffer.
     *
     * @param num is the ip address to convert and append
     * @param msg is the message to append to
     */
    private void appendIP(int num, LogMessage msg) {
        int parts[] = new int[4];

        for (int i = 3; i >= 0; i--) {
            parts[i] = num & 255;
            num >>>= 8;
        }
        for (int i = 0; i < 3; i++) {
            msg.getOutputBuffer().append(parts[i]);
            msg.getOutputBuffer().append('.');
            num >>>= 8;
        }
        msg.getOutputBuffer().append(parts[3]);
    }

    /**
     * Checks if an ip address (saved as an integer) is already saved in the hashmap.
     * If it is, appends the saved anonymized address to the message output. If
     * it is not present in the hashmap, anonymizes and saves it before appending.
     *
     * @param num is the address represented as an integer
     * @param msg is the currently worked on message
     */
    private void findIP(int num, LogMessage msg) {
        Integer ip = (Integer) hash.get(num);
        if (ip == null) {
            ip = codeInt(num, msg.getRand());
            hash.put(num, ip);
        }
        appendIP(ip, msg);
    }


    /**
     * anonymizes an IPv4 address and adds it to the output buffer of the message
     *
     * @param msg is the message to anonymize
     */
    @Override
    public void anonymize(LogMessage msg) {
        int intAddress;

        if (syntax(msg)) {
            intAddress = ip2num();
            if (cons) {
                findIP(intAddress, msg);
            } else {
                intAddress = codeInt(intAddress, msg.getRand());
                appendIP(intAddress, msg);
            }
        }
    }


    /**
     * default constructor, initializes defaults
     */
    public Ipv4Anonymizer() {
        ipParts = new int[4];
        bits = 16;
        mode = ipv4mode.ZERO;
        cons = false;
    }


    /**
     * reads the configuration for the IPv4 type
     *
     * @param prop is he property to read from
     */
    @Override
    public void getConfig(Properties prop) {
        String var;

        var = prop.getProperty("ipv4.bits");
        if (var != null) {
            bits = Integer.parseInt(var);
        }

        if (bits < 1 || bits > 32) {
            System.err.println("preference error: invalid number of ipv4.bits (" + bits + "), corrected to 32");
            bits = 32;
        }

        var = prop.getProperty("ipv4.mode");
        if (var != null) {
            if (var.contentEquals("zero")) {
                mode = ipv4mode.ZERO;
            } else if (var.contentEquals("random")) {
                mode = ipv4mode.RANDOM;
            } else if (var.contentEquals("random-consistent")) {
                mode = ipv4mode.RANDOM;
                cons = true;
            }
        }

        if (cons) {
            hash = new Hashtable<Integer, Integer>();
        }
    }

}
