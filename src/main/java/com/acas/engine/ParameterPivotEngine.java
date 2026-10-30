package com.acas.engine;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameterType;
import com.acas.model.ActorProfile;
import java.util.ArrayList;
import java.util.List;

public class ParameterPivotEngine {

    private static final String[] PIVOT_KEYWORDS = {
        "admin", "internal", "test", "debug", "all", "system", "superuser", "root", "dev", "staging", "private", "restricted", "config", "setup",
        "true", "false", "null", "undefined", "0", "1", "*", "%"
    };

    private static final String[] PIVOT_NAMES = {
        "role", "admin", "privilege", "access", "level", "type", "scope", "internal", "debug", "test", "dev", "staging", "private", "restricted", "config", "setup"
    };

    public List<MutationVector> generatePivotVectors(HttpRequest original, ActorProfile targetActor) {
        List<MutationVector> vectors = new ArrayList<>();
        
        // Value Pivoting
        for (burp.api.montoya.http.message.params.HttpParameter param : original.parameters()) {
            if (param == null || param.type() != HttpParameterType.URL) {
                continue;
            }
            String name = param.name();
            
            for (String keyword : PIVOT_KEYWORDS) {
                HttpRequest mutated = original.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(name, keyword, param.type())
                );
                vectors.add(new MutationVector("P1", targetActor, "Value Pivot: " + name + "=" + keyword, mutated));
            }
        }

        // Name Pivoting (Swap parameter names)
        for (burp.api.montoya.http.message.params.HttpParameter param : original.parameters()) {
            if (param == null || param.type() != HttpParameterType.URL) {
                continue;
            }
            for (String newName : PIVOT_NAMES) {
                if (param.name().equalsIgnoreCase(newName)) continue;
                HttpRequest mutated = original.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(newName, param.value(), param.type())
                );
                vectors.add(new MutationVector("P2", targetActor, "Name Pivot: " + param.name() + " -> " + newName, mutated));
            }
        }
        
        return vectors;
    }
}
