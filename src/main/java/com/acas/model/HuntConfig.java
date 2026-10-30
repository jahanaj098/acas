package com.acas.model;

public class HuntConfig {
    private final String targetHost;
    private final String startTime;
    private final String endTime;

    public HuntConfig(String targetHost, String startTime, String endTime) {
        this.targetHost = targetHost;
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public String getTargetHost() {
        return targetHost;
    }

    public String getStartTime() {
        return startTime;
    }

    public String getEndTime() {
        return endTime;
    }
}
