package com.rsyslog.slfa.model;

import java.util.Random;

/**
 * class to store the message that is currently worked on and additional information
 *
 * @author Jan Gerhards
 */
public class LogMessage {
    private static final Random RAND = new Random(System.currentTimeMillis());

    private final StringBuffer _outputBuffer = new StringBuffer();
    private String _inputMessage;
    private int _processedChars;
    private int _currentIndex;

    /**
     * getter for the message that is currently being processed
     *
     * @return the message
     */
    public String getInputMessage() {
        return _inputMessage;
    }

    /**
     * setter for the message being worked on
     *
     * @param inputMessage is the new message
     */
    public void setInputMessage(String inputMessage) {
        _inputMessage = inputMessage;
        _currentIndex = 0;
    }

    /**
     * getter for the output buffer
     *
     * @return output buffer
     */
    public StringBuffer getOutputBuffer() {
        return _outputBuffer;
    }

    /**
     * getter for the number of characters processed so far
     * note: this refers to the character processed by an anonymization
     * type, not the current index
     *
     * @return the number of processed characters
     */
    public int getProcessedChars() {
        return _processedChars;
    }

    /**
     * setter for the number of characters processed so far
     * note: this refers to the character processed by an anonymization
     * type, not the current index
     *
     * @param processedChars is the number of characters processed
     */
    public void setProcessedChars(int processedChars) {
        _processedChars = processedChars;
    }

    /**
     * adds a value to nProcessed
     *
     * @param toAdd is the value to add
     */
    public void increaseProcessedChars(int toAdd) {
        _processedChars += toAdd;
    }

    /**
     * getter for the current index
     *
     * @return the current index
     */
    public int getCurrentIndex() {
        return _currentIndex;
    }

    /**
     * setter for the current index
     *
     * @param currentIndex is the current index
     */
    public void setCurrentIndex(int currentIndex) {
        _currentIndex = currentIndex;
    }

    /**
     * getter for the randomizer
     *
     * @return rand
     */
    public Random getRand() {
        return RAND;
    }

    /**
     * prints the anonymized message on StdOut and deletes the output buffer
     */
    public void popPrintAnonymizedBuffer() {
        System.out.println(_outputBuffer);
        if (_outputBuffer.length() > 0) {
            _outputBuffer.delete(0, _outputBuffer.length());
        }
    }
}
