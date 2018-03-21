package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.LogMessage;

import java.util.Properties;

/**
 * anonymization type that is used when  no other type fits
 *
 * @author Jan Gerhards
 */
public class NoneAnonymizer implements Anonymizer {


    /**
     * appends the next character of a message to its output buffer
     *
     * @param msg is the message
     */
    @Override
    public void anonymize(LogMessage msg) {
        msg.getOutputBuffer().append(msg.getInputMessage().charAt(msg.getCurrentIndex()));
        msg.setProcessedChars(1);
    }

    /**
     * empty, since no configuration is needed for this type
     */
    @Override
    public void getConfig(Properties prop) {
    }
}
