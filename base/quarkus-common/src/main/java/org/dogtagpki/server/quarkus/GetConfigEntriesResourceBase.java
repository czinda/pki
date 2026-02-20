//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.quarkus;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.StringTokenizer;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import com.netscape.certsrv.base.EBaseException;
import org.dogtagpki.util.cert.CertUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Node;

import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmsutil.password.PasswordStore;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * Abstract base JAX-RS resource replacing the legacy GetConfigEntries CMSServlet.
 * Returns configuration entries as XML for inter-subsystem communication during deployment.
 * Each subsystem extends this with a concrete @Path annotation.
 */
public abstract class GetConfigEntriesResourceBase {

    private static final Logger logger = LoggerFactory.getLogger(GetConfigEntriesResourceBase.class);
    private static final String SUCCESS = "0";

    protected abstract CMSEngine getEngine();

    @GET
    @Produces(MediaType.APPLICATION_XML)
    public Response getConfigEntries(
            @QueryParam("op") String op,
            @QueryParam("substores") String substores,
            @QueryParam("names") String names) {

        logger.info("GetConfigEntriesResourceBase: op={}", op);

        CMSEngine engine = getEngine();
        EngineConfig config = engine.getConfig();

        try {
            XMLObject xmlObj = new XMLObject();
            Node root = xmlObj.createRoot("XMLResponse");

            if (op != null) {
                // Process substores
                if (substores != null && !substores.isEmpty()) {
                    logger.info("GetConfigEntriesResourceBase: Processing substores");
                    StringTokenizer t = new StringTokenizer(substores, ",");
                    while (t.hasMoreTokens()) {
                        String name1 = t.nextToken();
                        ConfigStore cs = config.getSubStore(name1, ConfigStore.class);
                        Enumeration<String> enum1 = cs.getPropertyNames();
                        while (enum1.hasMoreElements()) {
                            String propName = name1 + "." + enum1.nextElement();
                            String value = config.getString(propName, null);
                            if ("localhost".equals(value)) {
                                value = config.getHostname();
                            }
                            Node container = xmlObj.createContainer(root, "Config");
                            xmlObj.addItemToContainer(container, "name", propName);
                            xmlObj.addItemToContainer(container, "value", value);
                        }
                    }
                }

                // Process names
                if (names != null && !names.isEmpty()) {
                    logger.info("GetConfigEntriesResourceBase: Processing names");
                    StringTokenizer t1 = new StringTokenizer(names, ",");
                    while (t1.hasMoreTokens()) {
                        String name = t1.nextToken();
                        String value;

                        if (name.equals("internaldb.ldapauth.password")) {
                            value = getLDAPPassword(engine);
                        } else if (name.equals("internaldb.replication.password")) {
                            value = getReplicationPassword(engine);
                        } else if (name.endsWith(".certreq")) {
                            value = getCSR(name);
                        } else {
                            value = config.getString(name, null);
                            if ("localhost".equals(value)) {
                                value = config.getHostname();
                            }
                        }

                        if (value != null) {
                            Node container = xmlObj.createContainer(root, "Config");
                            xmlObj.addItemToContainer(container, "name", name);
                            xmlObj.addItemToContainer(container, "value", value);
                        }
                    }
                }
            }

            xmlObj.addItemToContainer(root, "Status", SUCCESS);
            return Response.ok(new String(xmlObj.toByteArray()), MediaType.APPLICATION_XML).build();

        } catch (Exception e) {
            logger.error("GetConfigEntriesResourceBase: Error", e);
            return Response.serverError().entity("Error: " + e.getMessage()).build();
        }
    }

    private String getLDAPPassword(CMSEngine engine) throws Exception {
        PasswordStore pwdStore = engine.getPasswordStore();
        return pwdStore.getPassword("internaldb", 0);
    }

    private String getReplicationPassword(CMSEngine engine) throws Exception {
        PasswordStore pwdStore = engine.getPasswordStore();
        return pwdStore.getPassword("replicationdb", 0);
    }

    @Deprecated(since = "11.5.0")
    private String getCSR(String param) {
        String[] paramParts = param.split("\\.");
        String csrFileName;

        if (paramParts[1].equals("sslserver") || paramParts[1].equals("subsystem")) {
            csrFileName = paramParts[1] + ".csr";
        } else {
            csrFileName = paramParts[0] + "_" + paramParts[1] + ".csr";
        }

        Path csrPath = FileSystems.getDefault().getPath(CMS.getInstanceDir(), "conf", "certs", csrFileName);
        try {
            String csr = Files.readString(csrPath);
            return CertUtil.unwrapCSR(csr, true);
        } catch (IOException | EBaseException e) {
            logger.warn("GetConfigEntriesResourceBase: Cannot access CSR file {}", csrPath, e);
            return null;
        }
    }
}
