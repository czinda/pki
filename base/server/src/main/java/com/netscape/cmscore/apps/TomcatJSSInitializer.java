package com.netscape.cmscore.apps;

import java.lang.reflect.Method;

/**
 * Initializes JSS via TomcatJSS using reflection to avoid
 * compile-time dependency on the jss-tomcat package.
 */
public class TomcatJSSInitializer implements JSSInitializer {
    @Override
    public void initialize() throws Exception {
        Class<?> clazz = Class.forName("org.dogtagpki.jss.tomcat.TomcatJSS");
        Method getInstance = clazz.getMethod("getInstance");
        Object tomcatjss = getInstance.invoke(null);
        clazz.getMethod("loadConfig").invoke(tomcatjss);
        clazz.getMethod("init").invoke(tomcatjss);
    }
}
