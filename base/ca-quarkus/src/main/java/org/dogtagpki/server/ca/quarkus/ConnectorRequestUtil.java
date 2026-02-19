//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.io.ByteArrayOutputStream;

import org.mozilla.jss.netscape.security.x509.CertificateAlgorithmId;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.CertificateValidity;
import org.mozilla.jss.netscape.security.x509.CertificateX509Key;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.cmscore.request.Request;

/**
 * Utility methods for connector request normalization.
 * Extracted from ConnectorServlet for reuse.
 */
public class ConnectorRequestUtil {

    private static final Logger logger = LoggerFactory.getLogger(ConnectorRequestUtil.class);

    public static void normalizeProfileRequest(Request request) {
        try {
            X509CertInfo info = request.getExtDataInCertInfo(Request.REQUEST_CERTINFO);
            if (info == null) return;

            CertificateX509Key certKey = (CertificateX509Key) info.get(X509CertInfo.KEY);
            if (certKey != null) {
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                certKey.encode(byteStream);
                request.setExtData(Request.REQUEST_KEY, byteStream.toByteArray());
            }

            CertificateSubjectName certSubject = (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);
            if (certSubject != null) {
                request.setExtData(Request.REQUEST_SUBJECT_NAME, certSubject);
            }

            CertificateValidity certValidity = (CertificateValidity) info.get(X509CertInfo.VALIDITY);
            if (certValidity != null) {
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                certValidity.encode(byteStream);
                request.setExtData(Request.REQUEST_VALIDITY, byteStream.toByteArray());
            }

            CertificateExtensions extensions = (CertificateExtensions) info.get(X509CertInfo.EXTENSIONS);
            if (extensions != null) {
                request.setExtData(Request.REQUEST_EXTENSIONS, extensions);
            }

            CertificateAlgorithmId certAlg = (CertificateAlgorithmId) info.get(X509CertInfo.ALGORITHM_ID);
            if (certAlg != null) {
                ByteArrayOutputStream certAlgOut = new ByteArrayOutputStream();
                certAlg.encode(certAlgOut);
                request.setExtData(Request.REQUEST_SIGNING_ALGORITHM, certAlgOut.toByteArray());
            }
        } catch (Exception e) {
            logger.warn("ConnectorRequestUtil: profile normalization error", e);
        }
    }
}
