package com.acas.engine;

import burp.api.montoya.http.message.responses.HttpResponse;

public class EndpointBaseline {
    public HttpResponse authenticatedResponse;
    public HttpResponse anonymousResponse;
    public HttpResponse invalidIdResponse;
    public HttpResponse nonExistentResponse;
    public long capturedAtEpochMs;
}
