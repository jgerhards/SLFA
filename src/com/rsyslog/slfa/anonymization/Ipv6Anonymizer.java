package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.LogMessage;
import com.rsyslog.slfa.model.Ipv6;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;


/**
 * Type to anonymize IPv6 addresses
 *
 * @author Jan Gerhards
 */
public class Ipv6Anonymizer implements Anonymizer {

    private enum anonmode {ZERO, RANDOM}

    private anonmode mode;
    private boolean cons;
    private int bits;
    private Hashtable<Ipv6, Ipv6> hash;


    /**
     * reads a message starting at the next unprocessed character
     * and returns the length of a hexadecimal number if present or -1,
     * if the next unprocessed character is ':'
     *
     * @param msg is the message
     * @return the length of the hexadecimal number or -1 if the first character is ':'
     */
    private int validHexVal(LogMessage msg) {
        int buflen = msg.getInputMessage().length();
        int idx = msg.getCurrentIndex() + msg.getProcessedChars();
        int cyc = 0;

        while (idx < buflen) {
            switch (msg.getInputMessage().charAt(idx)) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':

                case 'a':
                case 'b':
                case 'c':
                case 'd':
                case 'e':
                case 'f':

                case 'A':
                case 'B':
                case 'C':
                case 'D':
                case 'E':
                case 'F':
                    cyc++;
                    msg.setProcessedChars(msg.getProcessedChars() + 1);
                    if (cyc == 5) {
                        return 0;
                    }
                    break;
                case ':':
                    if (cyc == 0) {
                        msg.setProcessedChars(msg.getProcessedChars() + 1);
                        return -1;
                    }  //no break so it return cyc if cyc != 0
                default:
                    return cyc;
            }
            idx++;
        }
        return cyc;
    }


    /**
     * checks if the message starts with an IPv6 address
     * at the current index
     *
     * @param msg is the message to check
     * @return true, if the message starts with an IPv6 address
     * at the current index, else false
     */
    private boolean syntax(LogMessage msg) {
        boolean lastSep = false;
        boolean hadAbbrev = false;
        boolean lastAbbrev = false;
        int ipParts = 0;
        int numLen;
        int buflen = msg.getInputMessage().length();

        while (msg.getProcessedChars() < buflen) {
            numLen = validHexVal(msg);
            if (numLen > 0) {  //found a valid num
                if ((ipParts == 7 && hadAbbrev) || ipParts > 7) {
                    return false;
                }
                if (ipParts == 0 && lastSep && !hadAbbrev) {
                    return false;
                }
                lastSep = false;
                lastAbbrev = false;
                ipParts++;
            } else if (numLen < 0) {  //':'
                if (lastSep) {
                    if (hadAbbrev) {
                        return false;
                    } else {
                        hadAbbrev = true;
                        lastAbbrev = true;
                    }
                }
                lastSep = true;
            } else {  //no valid num
                if (lastSep) {
                    return lastAbbrev && ipParts < 8;
                }
                return (ipParts == 8 && !hadAbbrev) || (ipParts < 8 && hadAbbrev);
            }
        }

        return (!lastSep && (ipParts == 8 && !hadAbbrev)) || (ipParts < 8 && hadAbbrev);
    }


    /**
     * returns the hexadecimal value of a character
     *
     * @param c is the character to calculate the value for
     * @return the hexadecimal value of c
     */
    private int getHexVal(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0';
        } else if ('a' <= c && c <= 'f') {
            return (c - 'a') + 10;
        } else if ('A' <= c && c <= 'F') {
            return (c - 'A') + 10;
        } else {
            return -1;
        }
    }


    /**
     * converts the IPv6 address in a message to an Ipv6
     * starting at the current index of the message.
     *
     * @param msg is the message
     * @return the ip address in the message starting at the current index
     */
    private Ipv6 ip2int(LogMessage msg) {
        Ipv6 ip = new Ipv6();
        int num[] = {0, 0, 0, 0, 0, 0, 0, 0};
        int cyc = 0;
        int dots = 0;
        int val;
        int i;
        int iplen = msg.getProcessedChars();

        int endIP = msg.getCurrentIndex() + iplen;
        for (i = msg.getCurrentIndex(); i < endIP && dots < 2; i++) {
            val = getHexVal(msg.getInputMessage().charAt(i));
            if (val == -1) {
                dots++;
                if (dots < 2) {
                    cyc++;
                }
            } else {
                num[cyc] = num[cyc] * 16 + val;
                dots = 0;
            }
        }
        if (dots == 2) {
            if (i < iplen - 1) {
                int shift = 0;
                cyc = 7;
                for (int j = iplen - 1; j >= i; j--) {
                    val = getHexVal(msg.getInputMessage().charAt(j));
                    if (val == -1) {
                        cyc--;
                        shift = 0;
                    } else {
                        val <<= shift;
                        shift += 4;
                        num[cyc] += val;
                    }
                }
            } else {
                while (cyc < 8) {
                    num[cyc] = 0;
                    cyc++;
                }
            }
        }

        for (i = 0; i < 4; i++) {
            ip.setHigh(ip.getHigh() << 16);
            ip.setHigh(ip.getHigh() | num[i]);
        }
        while (i < 8) {
            ip.setLow(ip.getLow() << 16);
            ip.setLow(ip.getLow() | num[i]);
            i++;
        }

        return ip;

    }


    /**
     * anonymizes an ip address
     *
     * @param ip   is the address to anonymize represented as an Ipv6
     */
    private void code_ipv6_int(Ipv6 ip, LogMessage msg) {
        Random rand = msg.getRand();
        int bitscpy = bits;

        if (bitscpy == 128) { //has to be handled separately, since shift
            //128 bits doesn't work on unsigned long long
            ip.setHigh(0);
            ip.setLow(0);
        } else if (bitscpy > 64) {
            ip.setLow(0);
            ip.setHigh((ip.getHigh() >>> (bitscpy - 64)) << (bitscpy - 64));
        } else if (bitscpy == 64) {
            ip.setLow(0);
        } else {
            ip.setLow((ip.getLow() >>> bitscpy) << bitscpy);
        }
        switch (mode) {
            case ZERO:
                break;
            case RANDOM:
                if (bitscpy == 128) {
                    ip.setHigh(rand.nextLong());
                    ip.setLow(rand.nextLong());
                } else if (bitscpy > 64) {
                    ip.setLow(rand.nextLong());
                    ip.setHigh(ip.getHigh() | (rand.nextLong() & ((1L << (bitscpy - 64)) - 1)));
                } else if (bitscpy == 64) {
                    ip.setLow(rand.nextLong());
                } else {
                    ip.setLow(ip.getLow() | (rand.nextLong() & ((1L << bitscpy) - 1)));
                }
                break;
            default:
                System.err.println("error: unexpected code reached");
        }
    }

    /**
     * converts an Ipv6 to a string representation of an IPv6 address
     * and appends it to the output buffer of a message
     *
     * @param ip  is the ip address
     * @param msg is the message to append to
     */
    private void appendIP(Ipv6 ip, LogMessage msg) {
        int num[] = new int[8];
        int i;
        Ipv6 ipcpy;

        if (cons) {
            ipcpy = new Ipv6();
            ipcpy.setHigh(ip.getHigh());
            ipcpy.setLow(ip.getLow());
        } else {
            ipcpy = ip;
        }

        for (i = 7; i > 3; i--) {
            num[i] = (int) (ipcpy.getLow() & 0xffff);
            ipcpy.setLow(ipcpy.getLow() >>> 16);
        }
        while (i > -1) {
            num[i] = (int) (ipcpy.getHigh() & 0xffff);
            ipcpy.setHigh(ipcpy.getHigh() >>> 16);
            i--;
        }

        for (int j = 0; j < 7; j++) {
            msg.getOutputBuffer().append(Integer.toHexString(num[j]));
            msg.getOutputBuffer().append(':');
        }
        msg.getOutputBuffer().append(Integer.toHexString(num[7]));

    }


    /**
     * Checks if an ip address is already saved in the hashmap.
     * If it is, appends the saved anonymized address to the message output. If
     * it is not present in the hashmap, anonymizes and saves it before appending.
     *
     * @param msg is the currently worked on message
     * @param num is the address
     */
    private void findIP(LogMessage msg, Ipv6 num) {
        Ipv6 ip = hash.get(num);
        if (ip == null) {
            ip = new Ipv6();
            ip.setHigh(num.getHigh());
            ip.setLow(num.getLow());
            code_ipv6_int(ip, msg);
            hash.put(num, ip);
        }
        appendIP(ip, msg);
    }


    /**
     * anonymizes an IPv6 address and adds it to the output buffer of the message
     *
     * @param msg is the message to anonymize
     */
    @Override
    public void anonymize(LogMessage msg) {
        if (syntax(msg)) {
            Ipv6 ip = ip2int(msg);
            if (cons) {
                findIP(msg, ip);
            } else {
                code_ipv6_int(ip, msg);
                appendIP(ip, msg);
            }
        } else {
            msg.setProcessedChars(0);
        }
    }


    /**
     * reads the configuration for the IPv4 type
     *
     * @param prop is the property to read from
     */
    @Override
    public void getConfig(Properties prop) {
        String var;

        var = prop.getProperty("ipv6.bits");
        if (var != null) {
            bits = Integer.parseInt(var);
        }

        if (bits < 1 || bits > 128) {
            System.err.println("preference error: invalid number of ipv4.bits (" + bits + "), corrected to 128");
            bits = 128;
        }

        var = prop.getProperty("ipv6.mode");
        if (var != null) {
            if (var.contentEquals("zero")) {
                mode = anonmode.ZERO;
            } else if (var.contentEquals("random")) {
                mode = anonmode.RANDOM;
            } else if (var.contentEquals("random-consistent")) {
                mode = anonmode.RANDOM;
                cons = true;
            }
        }

        if (cons) {
            hash = new Hashtable<>();
        }
    }


    /**
     * default constructor, initializes defaults
     */
    public Ipv6Anonymizer() {
        bits = 96;
        mode = anonmode.ZERO;
        cons = false;
    }

}
