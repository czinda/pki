//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.acme.cli;

import java.io.File;
import java.io.FileReader;
import java.util.Properties;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLI;
import org.dogtagpki.server.cli.ServerCommandCLI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cms.realm.PKIRealmCore;
import com.netscape.cms.realm.RealmCoreConfig;
import com.netscape.cmscore.apps.CMS;

/**
 * @author Endi S. Dewata
 */
public class ACMERealmInitCLI extends ServerCommandCLI {

    public static Logger logger = LoggerFactory.getLogger(ACMERealmInitCLI.class);

    public ACMERealmInitCLI(CLI parent) {
        super("init", "Initialize " + parent.getParent().getName().toUpperCase() + " realm", parent);
    }

    public ACMERealmInitCLI(String name, String description, CLI parent) {
        super(name, description, parent);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        initializeJSS();

        String instanceDir = CMS.getInstanceDir();
        String serverConfDir = instanceDir + File.separator + "conf";
        String acmeConfDir = serverConfDir + File.separator + "acme";
        logger.info("ACME configuration directory: " + acmeConfDir);

        File realmConfigFile = new File(acmeConfDir + File.separator + "realm.conf");
        RealmCoreConfig realmConfig;

        if (realmConfigFile.exists()) {
            logger.info("Loading ACME realm config from " + realmConfigFile);
            Properties realmProps = new Properties();
            try (FileReader reader = new FileReader(realmConfigFile)) {
                realmProps.load(reader);
            }
            realmConfig = RealmCoreConfig.fromProperties(realmProps);

        } else {
            logger.info("Loading default ACME realm config");
            realmConfig = new RealmCoreConfig();
        }

        String className = realmConfig.getClassName();
        Class<PKIRealmCore> realmClass = (Class<PKIRealmCore>) Class.forName(className);

        PKIRealmCore realm = realmClass.getDeclaredConstructor().newInstance();
        realm.setConfig(realmConfig);

        try {
            logger.info("Initializing ACME realm");
            realm.init();

        } finally {
            realm.stop();
        }
    }
}
