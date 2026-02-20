//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.math.BigInteger;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.util.JSONSerializer;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;

/**
 * JAX-RS resource for CA installer operations.
 * Replaces CAInstallerServlet.
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author alee
 */
@Path("v2/installer")
public class CAInstallerResource {

    private static final Logger logger = LoggerFactory.getLogger(CAInstallerResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @POST
    @Path("createRequestID")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createRequestID(String requestData) throws Exception {
        logger.info("CAInstallerResource: Creating request ID");

        CertificateSetupRequest certReqData = JSONSerializer.fromJSON(requestData, CertificateSetupRequest.class);

        CAEngine engine = engineQuarkus.getEngine();
        validatePin(engine, certReqData.getPin());

        CAEngineConfig cs = engine.getConfig();
        String csState = cs.getState() + "";

        if (csState.equals("1")) {
            throw new BadRequestException("System already configured");
        }

        CertRequestRepository requestRepository = engine.getCertRequestRepository();
        RequestId requestID = requestRepository.createRequestID();
        logger.info("CAInstallerResource: - request ID: {}", requestID.toHexString());

        return Response.ok(requestID.toJSON()).build();
    }

    @POST
    @Path("createCertID")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response createCertID(String requestData) throws Exception {
        logger.info("CAInstallerResource: Creating cert ID");

        CertificateSetupRequest certReqData = JSONSerializer.fromJSON(requestData, CertificateSetupRequest.class);

        CAEngine engine = engineQuarkus.getEngine();
        validatePin(engine, certReqData.getPin());

        CAEngineConfig cs = engine.getConfig();
        String csState = cs.getState() + "";

        if (csState.equals("1")) {
            throw new BadRequestException("System already configured");
        }

        CertificateRepository certificateRepository = engine.getCertificateRepository();
        BigInteger serialNumber = certificateRepository.getNextSerialNumber();
        CertId certID = new CertId(serialNumber);

        logger.info("CAInstallerResource: - cert ID: {}", certID.toHexString());

        return Response.ok(certID.toJSON()).build();
    }

    private void validatePin(CAEngine engine, String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        CAEngineConfig cs = engine.getConfig();
        PreOpConfig preopConfig = cs.getPreOpConfig();
        String preopPin = preopConfig.getString("pin");

        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
