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
// (C) 2019 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.netscape.security.pkcs.ContentInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.pkcs.SignerInfo;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.AlgorithmId;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestQueue;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.AdminSetupRequest;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.DomainInfo;
import com.netscape.certsrv.system.FinalizeConfigRequest;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.CertInfoProfile;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.cert.CertUtils;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.ldapconn.LdapBoundConnFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;

public class CAConfigurator extends Configurator {

    public CAConfigurator(CMSEngine engine) {
        super(engine);
    }

    public Cert setupCert(CertificateSetupRequest request) throws Exception {
        Cert cert = super.setupCert(request);

        String subsystem = cert.getSubsystem();
        String tag = request.getTag();

        if (subsystem.equals("ca") && tag.equals("signing")) {
            logger.info("CAConfigurator: Initializing CA with signing cert");

            CAEngine engine = CAEngine.getInstance();
            CAEngineConfig engineConfig = engine.getConfig();

            CertificateAuthority ca = engine.getCA();
            ca.setConfig(engineConfig.getCAConfig());
            ca.initCertSigningUnit();
        }

        return cert;
    }

    public PKCS7 createCertChain(X509CertImpl cert) throws IOException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        X509Certificate[] caCerts = ca.getCACertChain().getChain();
        X509Certificate[] certs = new X509Certificate[caCerts.length + 1];

        certs[0] = cert;
        for (int i=0; i < caCerts.length; i++) {
            certs[i + 1] = caCerts[i];
        }

        return new PKCS7(
                new AlgorithmId[0],
                new ContentInfo(new byte[0]),
                certs,
                new SignerInfo[0]);
    }

    public void createLocalAdminCert(String certRequest, String certRequestType, String subject) throws Exception {

        byte[] binRequest = Utils.base64decode(certRequest);
        X509Key x509key;

        if (certRequestType.equals("crmf")) {
            SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binRequest);
            subject = CryptoUtil.getSubjectName(crmfMsgs);
            x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

        } else if (certRequestType.equals("pkcs10")) {
            PKCS10 pkcs10 = new PKCS10(binRequest);
            x509key = pkcs10.getSubjectPublicKeyInfo();

        } else {
            throw new Exception("Certificate request type not supported: " + certRequestType);
        }

        if (x509key == null) {
            logger.error("CAConfigurator: Missing admin key");
            throw new IOException("Missing admin key");
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String caType = preopConfig.getString("cert.admin.type", "local");
        String dn = preopConfig.getString("cert.admin.dn");
        String issuerDN = preopConfig.getString("cert.signing.dn", "");

        String caSigningKeyType = preopConfig.getString("cert.signing.keytype", "rsa");
        String profileFile = cs.getString("profile.caAdminCert.config");
        String defaultSigningAlgsAllowed = cs.getString(
                "ca.profiles.defaultSigningAlgsAllowed", "SHA256withRSA,SHA256withEC,SHA1withDSA");
        String keyAlgorithm = CertUtils.getAdminProfileAlgorithm(
                caSigningKeyType, profileFile, defaultSigningAlgsAllowed);

        X509CertInfo info = CertUtils.createCertInfo(dn, issuerDN, keyAlgorithm, x509key, caType);

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        java.security.PrivateKey signingPrivateKey = ca.getSigningUnit().getPrivateKey();

        String instanceRoot = cs.getInstanceDir();
        String configurationRoot = cs.getString("configurationRoot");
        String profileName = preopConfig.getString("cert.admin.profile");
        logger.debug("CertUtil: profile: " + profileName);

        CertInfoProfile profile = new CertInfoProfile(instanceRoot + configurationRoot + profileName);

        // cfu - create request to enable renewal
        IRequestQueue queue = ca.getRequestQueue();

        IRequest req = CertUtils.createLocalRequest(
                queue,
                profile,
                info,
                x509key,
                null /* sanHostnames */,
                true /* installAdjustValidity */);

        RequestId reqId = req.getRequestId();
        preopConfig.putString("cert.admin.reqId", reqId.toString());

        String caSigningKeyAlgo;
        if (caType.equals("selfsign")) {
            caSigningKeyAlgo = preopConfig.getString("cert.signing.keyalgorithm", "SHA256withRSA");
        } else {
            caSigningKeyAlgo = preopConfig.getString("cert.signing.signingalgorithm", "SHA256withRSA");
        }
        logger.debug("Configurator: CA signing key algorithm: " + caSigningKeyAlgo);

        X509CertImpl impl = CertUtils.createLocalCert(
                req,
                profile,
                info,
                signingPrivateKey,
                caSigningKeyAlgo);

        // store request in db
        queue.updateRequest(req);

        // update the locally created request for renewal
        CertUtils.updateLocalRequest(reqId.toString(), binRequest, certRequestType, subject);

        if (ca != null) {
            PKCS7 pkcs7 = createCertChain(impl);
            byte[] bytes = pkcs7.getBytes();
            String base64 = Utils.base64encodeSingleLine(bytes);

            preopConfig.putString("admincert.pkcs7", base64);
        }

        preopConfig.putString("admincert.serialno.0", impl.getSerialNumber().toString(16));
    }

    public X509CertImpl createAdminCertificate(AdminSetupRequest request) throws Exception {

        logger.info("CAConfigurator: Generating admin cert");

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String adminSubjectDN = request.getAdminSubjectDN();

        createLocalAdminCert(
                request.getAdminCertRequest(),
                request.getAdminCertRequestType(),
                adminSubjectDN);

        String serialno = preopConfig.getString("admincert.serialno.0");

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        ICertificateRepository repo = ca.getCertificateRepository();

        return repo.getX509Certificate(new BigInteger(serialno, 16));
    }

    @Override
    public void getDatabaseGroups(Collection<String> groups) throws Exception {
        groups.add("Subsystem Group");
        groups.add("Certificate Manager Agents");
    }

    @Override
    public void finalizeConfiguration(FinalizeConfigRequest request) throws Exception {

        try {
            if (!request.isClone()) {
                updateNextRanges();
            }

        } catch (Exception e) {
            logger.error("Unable to update next serial number ranges: " + e.getMessage(), e);
            throw new PKIException("Unable to update next serial number ranges: " + e.getMessage(), e);
        }

        try {
            DomainInfo domainInfo = request.getDomainInfo();
            logger.info("Domain: " + domainInfo);

            if (request.isClone() && isSDHostDomainMaster(domainInfo)) {
                enableSecurityDomainOnClone();
            }

            if (request.isClone()) {
                disableCRLCachingAndGenerationForClone(request.getCloneUri());
            }

            configureStartingCRLNumber(request.getStartingCRLNumber());

        } catch (Exception e) {
            logger.error("Unable to determine if security domain host is a master CA: " + e.getMessage(), e);
            throw new PKIException("Unable to determine if security domain host is a master CA: " + e.getMessage(), e);
        }

        try {
            setSubsystemEnabled("profile", true);
        } catch (Exception e) {
            logger.error("Unable to enable profile subsystem: " + e.getMessage(), e);
            throw new PKIException("Unable to enable profile subsystem: " + e.getMessage(), e);
        }

        if (! request.createSigningCertRecord()) {
            // This is the migration case.  In this case, we will delete the
            // record that was created during the install process.

            try {
                String serialNumber = request.getSigningCertSerialNumber();
                deleteSigningRecord(serialNumber);
            } catch (Exception e) {
                logger.error("Unable to delete signing cert record: " + e.getMessage(), e);
                throw new PKIException("Unable to delete signing cert record: " + e.getMessage(), e);
            }
        }

        super.finalizeConfiguration(request);
    }

    public void enableSecurityDomainOnClone() throws Exception {

        // cloning a domain master CA, the clone is also master of its domain

        cs.putString("securitydomain.select", "new");
        cs.putString("securitydomain.host", engine.getEEHost());
        cs.putString("securitydomain.httpport", engine.getEENonSSLPort());
        cs.putString("securitydomain.httpsadminport", engine.getAdminPort());
        cs.putString("securitydomain.httpsagentport", engine.getAgentPort());
        cs.putString("securitydomain.httpseeport", engine.getEESSLPort());
    }

    public void disableCRLCachingAndGenerationForClone(String cloneUri) throws MalformedURLException {

        logger.debug("CAConfigurator: disabling CRL caching and generation for clone");

        //Now add some well know entries that we need to disable CRL functionality.
        //With well known values to disable and well known master CRL ID.

        cs.putInteger("ca.certStatusUpdateInterval", 0);
        cs.putBoolean("ca.listenToCloneModifications", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLCache", false);
        cs.putBoolean("ca.crl.MasterCRL.enableCRLUpdates", false);

        URL url = new URL(cloneUri);
        String masterHost = url.getHost();
        int masterPort = url.getPort();

        logger.debug("CAConfigurator: master host: " + masterHost);
        logger.debug("CAConfigurator: master port: " + masterPort);

        cs.putString("master.ca.agent.host", masterHost);
        cs.putInteger("master.ca.agent.port", masterPort);
    }

    public void configureStartingCRLNumber(String startingCrlNumber) {
        logger.debug("CAConfigurator: configuring starting CRL number");
        cs.putString("ca.crl.MasterCRL.startingCrlNumber", startingCrlNumber);
    }

    public void deleteSigningRecord(String serialNumber) throws EBaseException, LDAPException {

        if (StringUtils.isEmpty(serialNumber)) {
            throw new PKIException("Missing signing certificate serial number");
        }

        LDAPConnection conn = null;
        try {
            LDAPConfig dbCfg = cs.getInternalDBConfig();
            LdapBoundConnFactory dbFactory = new LdapBoundConnFactory("CAConfigurator");
            dbFactory.init(cs, dbCfg, engine.getPasswordStore());

            conn = dbFactory.getConn();

            String basedn = dbCfg.getBaseDN();
            String dn = "cn=" + serialNumber + ",ou=certificateRepository,ou=ca," + basedn;

            conn.delete(dn);

        } finally {
            try {
                if (conn != null) conn.disconnect();
            } catch (LDAPException e) {
                logger.warn("Unable to release connection: " + e.getMessage(), e);
            }
        }
    }
}
