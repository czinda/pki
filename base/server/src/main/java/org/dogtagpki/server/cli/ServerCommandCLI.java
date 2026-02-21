//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.cli;

import java.io.File;

import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.cli.CommandCLI;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.FileConfigStorage;
import com.netscape.cmscore.ldapconn.LDAPAuthenticationConfig;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapAuthInfo;
import com.netscape.cmscore.ldapconn.LdapConnInfo;
import com.netscape.cmsutil.password.PasswordStore;

/**
 * @author Chris S. Kelley
 */
public abstract class ServerCommandCLI extends CommandCLI {

    public static final Logger logger = LoggerFactory.getLogger(ServerCommandCLI.class);

    protected ServerCommandCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option("i", "instance", true, "Instance ID (default: pki-quarkus)");
        option.setArgName("instance ID");
        options.addOption(option);
    }

    protected void initializeJSS() {
        try {
            String instanceDir = CMS.getInstanceDir();
            if (instanceDir == null) {
                return;
            }
            String certdbDir = instanceDir + File.separator + "alias";
            if (!new File(certdbDir).exists()) {
                certdbDir = instanceDir + File.separator + "conf" + File.separator + "alias";
            }
            if (!new File(certdbDir).exists()) {
                logger.debug("NSS database not found, skipping JSS initialization");
                return;
            }
            logger.debug("Initializing JSS with NSS database: {}", certdbDir);
            InitializationValues iv = new InitializationValues(certdbDir);
            CryptoManager.initialize(iv);
        } catch (Exception e) {
            logger.debug("JSS initialization skipped: {}", e.getMessage());
        }
    }

    protected EngineConfig getEngineConfig(String subsystem) throws Exception {

        // use subsystem conf folder: /var/lib/pki/<instance>/conf/<subsystem>
        String confDir = CMS.getInstanceDir() + File.separator + "conf" + File.separator + subsystem;
        String configFile = confDir + File.separator + CMS.CONFIG_FILE;
        logger.debug("{}: Loading {}", getClass().getSimpleName(), configFile);

        ConfigStorage storage = new FileConfigStorage(configFile);
        return new EngineConfig(storage);
    }

    protected LdapAuthInfo getAuthInfo(PasswordStore passwordStore, LdapConnInfo connInfo, LDAPConfig ldapConfig)
            throws EBaseException {
        LDAPAuthenticationConfig authConfig = ldapConfig.getAuthenticationConfig();
        LdapAuthInfo authInfo = new LdapAuthInfo();
        authInfo.setPasswordStore(passwordStore);
        authInfo.init(
                authConfig,
                connInfo.getHost(),
                connInfo.getPort(),
                connInfo.getSecure());
        return authInfo;
    }

    protected String getSecurePort(EngineConfig config) throws Exception {

        String securePort = config.getString("service.securePort", "8443");

        String port = config.getString("proxy.securePort", "");
        if (!port.equals("")) {
            securePort = port;
        }
        return securePort;
    }
}
