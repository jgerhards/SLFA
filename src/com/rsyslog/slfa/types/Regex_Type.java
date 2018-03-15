package com.rsyslog.slfa.types;

import com.rsyslog.slfa.file.CurrMsg;

import java.util.Hashtable;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Type to anonymize regular expressions
 *
 * @author Jan Gerhards
 */
public class Regex_Type extends Type {
    private enum anonmode {REPLACE, RANDOM}

    ;

    private boolean jumpover;  //if no regex is given, ignore type

    private int num;
    private int lastStart;
    private anonmode mode;
    private String replace;
    private boolean keepNum;
    private boolean keepChar;
    private boolean keepSpChar;
    Pattern match;
    int end;
    boolean cons;
    Hashtable<String, StringBuffer> hash;


    /**
     * randomizes and appends a regular expression
     *
     * @param msg      is the message
     * @param regexLen is the length of the regular expression
     * @param rand     is the randomizer
     * @param idx      is the index at which to start
     * @param buff     is the buffer that the characters are appended to
     */
    private void randomizeRegex(String msg, int regexLen, Random rand, int idx, StringBuffer buff) {
        char c;

        for (int i = 0; i < regexLen; i++) {
            c = msg.charAt(idx + i);
            if (keepNum && c >= '0' && '9' >= c) {
                buff.append(c);
            } else if (keepChar && ((c >= 'a' && 'z' >= c) || (c >= 'A' && 'Z' >= c))) {
                buff.append(c);
            } else if (keepSpChar && !((c >= 'a' && 'z' >= c) || (c >= 'A' && 'Z' >= c) || (c >= '0' && '9' >= c))) {
                buff.append(c);
            } else {
                buff.append((char) (rand.nextInt((95)) + 32));
            }
        }
    }


    /**
     * append the anonymized regular expression to the message output buffer
     *
     * @param msg is the message
     */
    private void appendEnd(CurrMsg msg) {
        switch (mode) {
            case RANDOM:
                if (cons) {
                    String foundRegex = msg.getMsgIn().substring(msg.getCurrIdx(), msg.getCurrIdx() + msg.getNprocessed());
                    if (hash.containsKey(foundRegex)) {
                        msg.getMsgOut().append(hash.get(foundRegex));
                    } else {
                        StringBuffer anonRegex = new StringBuffer();
                        randomizeRegex(msg.getMsgIn(), msg.getNprocessed(), msg.getRand(), msg.getCurrIdx(), anonRegex);
                        hash.put(foundRegex, anonRegex);
                        msg.getMsgOut().append(anonRegex);
                    }
                } else {
                    randomizeRegex(msg.getMsgIn(), msg.getNprocessed(), msg.getRand(), msg.getCurrIdx(), msg.getMsgOut());
                }
                break;
            case REPLACE:
                msg.getMsgOut().append(replace);
                break;
        }
    }


    /**
     * anonymizes an IPv4 address and adds it to the output buffer of the message
     *
     * @param msg is the message to anonymize
     */
    private void real_anon(CurrMsg msg) {
        if (msg.getCurrIdx() == 0) {
            lastStart = -1;
        }
        Matcher m = match.matcher(msg.getMsgIn());
        if (lastStart < msg.getCurrIdx()) {
            if (m.find(msg.getCurrIdx())) {
                lastStart = m.start();
                end = m.end();
            }
        }
        if (lastStart > msg.getCurrIdx() || lastStart == -1) {
            return;
        } else if (lastStart == msg.getCurrIdx()) {
            msg.setNprocessed(end - lastStart);
            appendEnd(msg);
        }
    }


    /**
     * anonymizes an IPv4 address and adds it to the output buffer of the message
     * or does nothing, if the configuration is insufficient
     *
     * @param msg is the message to anonymize
     */
    @Override
    public void anon(CurrMsg msg) {
        if (jumpover) {
            return;
        } else {
            real_anon(msg);
        }
    }


    /**
     * reads advanced configuration for the random option
     *
     * @param prop is the property to read from
     */
    private void getRandomConfig(Properties prop) {
        mode = anonmode.RANDOM;
        String var = prop.getProperty("regex[" + num + "].keep");
        String[] split = var.split(" ");
        int splitnum = split.length;

        for (int i = 0; i < splitnum; i++) {
            char lastChar = split[i].charAt(split[i].length() - 1);
            while (lastChar == ',' || lastChar == ' ' || lastChar == ';') {
                split[i] = split[i].substring(0, split[i].length() - 1);
                split[i].trim();
                lastChar = split[i].charAt(split[i].length() - 1);
            }
            if (split[i].compareTo("num") == 0) {
                keepNum = true;
            }
            if (split[i].compareTo("char") == 0) {
                keepChar = true;
            }
            if (split[i].compareTo("spchar") == 0) {
                keepSpChar = true;
            }
        }
    }


    /**
     * reads the configuration for the IPv4 type
     *
     * @param prop is he property to read from
     */
    @Override
    public void getConfig(Properties prop) {
        String var;

        var = prop.getProperty("regex[" + num + "].in");
        if (var != null) {
            match = Pattern.compile(var);
        } else {
            System.out.println("no regular expression (regex[NUMBER_OF_REGEX].in) configured for regex[" + num + "], will be ignored");
            jumpover = true;
        }

        var = prop.getProperty("regex[" + num + "].mode");
        if (var != null) {
            if (var.contentEquals("replace")) {
                mode = anonmode.REPLACE;
                var = prop.getProperty("regex[" + num + "].replace");
                if (var != null) {
                    replace = var;
                }
            } else if (var.contentEquals("random-consistent")) {
                cons = true;
                getRandomConfig(prop);
            } else if (var.contentEquals("random")) {
                getRandomConfig(prop);
            }
        }
        if (cons) {
            hash = new Hashtable<String, StringBuffer>();
        }
    }


    /**
     * default constructor, initializes defaults
     */
    public Regex_Type(int name) {
        jumpover = false;
        num = name;
        mode = anonmode.RANDOM;
        keepNum = false;
        keepChar = false;
        keepSpChar = false;
        cons = false;
    }
}
