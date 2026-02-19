// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.apps;

import java.lang.reflect.Method;

import org.mozilla.jss.ssl.SSLSocketListener;

/**
 * Tomcat-based implementation of SocketListenerRegistry.
 *
 * Delegates to TomcatJSS for SSL socket listener management.
 * Uses reflection to avoid compile-time dependency on jss-tomcat.
 */
public class TomcatSocketListenerRegistry implements SocketListenerRegistry {

    private Object getTomcatJSS() throws Exception {
        Class<?> clazz = Class.forName("org.dogtagpki.jss.tomcat.TomcatJSS");
        return clazz.getMethod("getInstance").invoke(null);
    }

    @Override
    public void addSocketListener(SSLSocketListener listener) {
        try {
            Object tomcatJss = getTomcatJSS();
            Method method = tomcatJss.getClass().getMethod("addSocketListener", SSLSocketListener.class);
            method.invoke(tomcatJss, listener);
        } catch (Exception e) {
            throw new RuntimeException("Unable to add socket listener via TomcatJSS", e);
        }
    }

    @Override
    public void removeSocketListener(SSLSocketListener listener) {
        try {
            Object tomcatJss = getTomcatJSS();
            Method method = tomcatJss.getClass().getMethod("removeSocketListener", SSLSocketListener.class);
            method.invoke(tomcatJss, listener);
        } catch (Exception e) {
            throw new RuntimeException("Unable to remove socket listener via TomcatJSS", e);
        }
    }
}
