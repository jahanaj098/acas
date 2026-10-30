package com.acas.engine;

public class WriteOperationClassifier {

    public static class Result {
        public final String severity;
        public final boolean needsVerification;
        public final String note;

        public Result(String severity, boolean needsVerification, String note) {
            this.severity = severity;
            this.needsVerification = needsVerification;
            this.note = note;
        }
    }

    public Result classify(String method, int statusCode, int originalStatus) {
        if (method == null) return null;
        String m = method.toUpperCase();

        if (m.equals("DELETE")) {
            if (statusCode == 204 || statusCode == 200 || statusCode == 202) {
                return new Result("CRITICAL", true, "DELETE succeeded on another actor's resource.");
            }
        } else if (m.equals("POST")) {
            if (statusCode == 201) {
                return new Result("CRITICAL", false, "POST created a new resource under another actor's session.");
            }
            if (statusCode == 200 && originalStatus != 200) {
                return new Result("HIGH", false, "POST succeeded on an endpoint where owner gets " + originalStatus);
            }
        } else if (m.equals("PUT") || m.equals("PATCH")) {
            if (statusCode == 200 || statusCode == 204) {
                return new Result("HIGH", true, method + " succeeded on another actor's resource.");
            }
        }

        return null;
    }
}
