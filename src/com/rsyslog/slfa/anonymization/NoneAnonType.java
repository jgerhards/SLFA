package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.CurrMsg;

import java.util.Properties;

/**
 * anonymization type that is used when  no other type fits
 *
 * @author Jan Gerhards
 */
public class NoneAnonType extends AnonType {


    /**
     * appends the next character of a message to its output buffer
     *
     * @param msg is the message
     */
    @Override
    public void anon(CurrMsg msg) {
        msg.getMsgOut().append(msg.getMsgIn().charAt(msg.getCurrIdx()));
        msg.setNprocessed(1);
    }

    /**
     * empty, since no configuration is needed for this type
     */
    @Override
    public void getConfig(Properties prop) {
    }
}
