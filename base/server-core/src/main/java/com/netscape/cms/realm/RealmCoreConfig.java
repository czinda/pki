//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cms.realm;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Container-agnostic realm configuration.
 *
 * Provides parameter access without depending on any
 * container-specific configuration classes.
 */
public class RealmCoreConfig {

    private String className;
    private final Map<String, String> parameters = new LinkedHashMap<>();

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters.clear();
        this.parameters.putAll(parameters);
    }

    public Collection<String> getParameterNames() {
        return parameters.keySet();
    }

    public String getParameter(String name) {
        return parameters.get(name);
    }

    public void setParameter(String name, String value) {
        parameters.put(name, value);
    }

    public String removeParameter(String name) {
        return parameters.remove(name);
    }

    public static RealmCoreConfig fromProperties(Properties props) {
        RealmCoreConfig config = new RealmCoreConfig();
        for (Map.Entry<Object, Object> entry : props.entrySet()) {
            String key = entry.getKey().toString();
            String value = entry.getValue().toString();
            if (key.equals("class")) {
                config.setClassName(value);
            } else {
                config.setParameter(key, value);
            }
        }
        return config;
    }
}
