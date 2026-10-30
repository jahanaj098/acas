package com.acas.export;

/** One-shot, in-memory test fault. Never serialized into the restart queue. */
public final class HermesFailureSimulation {
    private final int destination,after;
    private boolean fired;
    public HermesFailureSimulation(int destination,int after) {
        if(destination<0 || destination>2 || after<0)throw new IllegalArgumentException("Invalid failure test");
        this.destination=destination;this.after=after;
    }
    public void beforeSend(boolean telegram,int acceptedThisAttempt) throws java.io.IOException {
        if(!fired && destination==(telegram?1:2) && acceptedThisAttempt>=after) {
            fired=true;
            throw new java.io.IOException("SIMULATED "+(telegram?"Telegram":"Discord")+" failure: this file was not sent. Close Burp and reopen Export for Hermes to test Resume saved delivery. The test resets automatically.");
        }
    }
}
