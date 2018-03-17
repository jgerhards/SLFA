package com.rsyslog.slfa.anonymization;

import com.rsyslog.slfa.model.CurrMsg;

import java.util.Properties;

/**
 * abstract class for all anonymization anonymization
 *
 * @author jan
 */
public abstract class AnonType {

    /**
     * function to call for every type before a new file is processed
     */
    public void onFileStart() {
    }

    /**
     * function to call for every type after a file has been processsed
     */
    public void onFileEnd() {
    }

    /**
     * anonymizes the message if it matches the anonymization type
     * starting at the index and adds the anonymized part to msgOut
     */
    public abstract void anon(CurrMsg msg);

    /**
     * reads the parameters for the type out of the preference file
     *
     * @param prop is the property to read out of
     */
    public abstract void getConfig(Properties prop);
}
