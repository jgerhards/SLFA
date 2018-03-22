package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.LogMessage;

import java.util.Properties;

/**
 * abstract class for all anonymization anonymization
 *
 * @author jan
 */
public interface Anonymizer {

    /**
     * anonymizes the message if it matches the anonymization type
     * starting at the index and adds the anonymized part to msgOut
     */
    void anonymize(LogMessage msg);

    /**
     * reads the parameters for the type out of the preference file
     *
     * @param prop is the property to read out of
     */
    void getConfig(Properties prop);
}
