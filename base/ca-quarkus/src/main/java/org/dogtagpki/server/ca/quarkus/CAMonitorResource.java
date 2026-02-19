//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.quarkus;

import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.netscape.ca.CertificateAuthority;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.dbs.DBSearchResults;
import com.netscape.cmscore.request.Request;
import com.netscape.cmscore.request.RequestRecord;
import com.netscape.cmscore.request.RequestRepository;

/**
 * JAX-RS resource replacing the legacy Monitor CMSServlet.
 * Provides statistical queries of request and certificate records
 * over specified time intervals.
 *
 * Legacy URL: /agent/ca/monitor
 *
 * Query parameters:
 * - startTime: start of time period (format: YYYYMMDDHHmmssZ or negative offset in seconds)
 * - endTime: (unused, computed from interval)
 * - interval: seconds per interval
 * - numberOfIntervals: number of intervals to query
 */
@Path("agent/ca/monitor")
public class CAMonitorResource {

    private static final Logger logger = LoggerFactory.getLogger(CAMonitorResource.class);

    @Inject
    CAEngineQuarkus engineQuarkus;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Response monitor(
            @QueryParam("startTime") String startTime,
            @QueryParam("interval") String interval,
            @QueryParam("numberOfIntervals") String numberOfIntervals) {

        logger.info("CAMonitorResource: Processing monitor request");

        CAEngine engine = engineQuarkus.getEngine();
        CertificateRepository certDB = engine.getCertificateRepository();
        RequestRepository requestRepository = engine.getRequestRepository();
        CertificateAuthority ca = engine.getCA();

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode result = mapper.createObjectNode();

        // Validate parameters
        if (interval == null || interval.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Invalid interval: " + interval);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        if (numberOfIntervals == null || numberOfIntervals.isEmpty()) {
            result.put("Status", "1");
            result.put("Error", "Invalid number of intervals: " + numberOfIntervals);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        Date startDate = stringToDate(startTime);
        if (startDate == null) {
            result.put("Status", "1");
            result.put("Error", "Invalid start time: " + startTime);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        int iInterval;
        try {
            iInterval = Integer.parseInt(interval);
        } catch (NumberFormatException e) {
            result.put("Status", "1");
            result.put("Error", "Invalid interval: " + interval);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        int iNumberOfIntervals;
        try {
            iNumberOfIntervals = Integer.parseInt(numberOfIntervals);
        } catch (NumberFormatException e) {
            result.put("Status", "1");
            result.put("Error", "Invalid number of intervals: " + numberOfIntervals);
            return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
        }

        result.put("startDate", startDate.toString());
        result.put("startTime", startTime);
        result.put("interval", iInterval);
        result.put("numberOfIntervals", iNumberOfIntervals);

        int totalCerts = 0;
        int totalReqs = 0;
        ArrayNode intervals = mapper.createArrayNode();

        Date d1 = startDate;

        for (int i = 0; i < iNumberOfIntervals; i++) {
            Date d2 = nextDate(d1, iInterval - 1);
            ObjectNode intervalNode = mapper.createObjectNode();

            String start = dateToZString(d1);
            String end = dateToZString(d2);
            intervalNode.put("startTime", start);
            intervalNode.put("endTime", end);

            try {
                // Count certificates created in this interval
                if (certDB != null) {
                    String filter = "(&(" + CertRecord.ATTR_CREATE_TIME + ">=" + start + ")("
                            + CertRecord.ATTR_CREATE_TIME + "<=" + end + "))";
                    DBSearchResults searchResults = certDB.findCertRecs(filter);
                    int certCount = 0;
                    while (searchResults != null && searchResults.hasMoreElements()) {
                        CertRecord rec = (CertRecord) searchResults.nextElement();
                        if (rec != null) {
                            certCount++;
                        }
                    }
                    intervalNode.put("numberOfCertificates", certCount);
                    totalCerts += certCount;
                }

                // Count requests created in this interval
                if (requestRepository != null) {
                    String filter = "(&(" + RequestRecord.ATTR_CREATE_TIME + ">=" + start + ")("
                            + RequestRecord.ATTR_CREATE_TIME + "<=" + end + "))";
                    Collection<RequestRecord> records = requestRepository.listRequestsByFilter(filter);
                    int reqCount = 0;
                    String firstRequest = null;
                    for (RequestRecord record : records) {
                        Request request = record.toRequest();
                        if (reqCount == 0) {
                            firstRequest = request.getRequestId().toString();
                        }
                        reqCount++;
                    }
                    intervalNode.put("numberOfRequests", reqCount);
                    if (firstRequest != null) {
                        intervalNode.put("firstRequest", firstRequest);
                    }
                    totalReqs += reqCount;
                }
            } catch (Exception e) {
                logger.error("CAMonitorResource: Error querying interval: {}", e.getMessage(), e);
                intervalNode.put("error", "Exception: " + e.getMessage());
            }

            intervals.add(intervalNode);
            d1 = nextDate(d2, 1);
        }

        result.put("totalNumberOfCertificates", totalCerts);
        result.put("totalNumberOfRequests", totalReqs);
        result.set("intervals", intervals);

        X500Name authName = ca != null ? ca.getX500Name() : null;
        if (authName != null) {
            result.put("issuerName", authName.toString());
        }

        result.put("Status", "0");
        return Response.ok(result.toString(), MediaType.APPLICATION_JSON).build();
    }

    /**
     * Parse a date string in either generalized time format (YYYYMMDDHHmmssZ)
     * or as a negative offset in seconds from the current time.
     */
    private Date stringToDate(String z) {
        if (z == null) return null;

        if (z.length() == 14 ||
                (z.length() == 15 && (z.charAt(14) == 'Z' || z.charAt(14) == 'z'))) {
            try {
                int year = Integer.parseInt(z.substring(0, 4));
                int month = Integer.parseInt(z.substring(4, 6)) - 1;
                int date = Integer.parseInt(z.substring(6, 8));
                int hour = Integer.parseInt(z.substring(8, 10));
                int minute = Integer.parseInt(z.substring(10, 12));
                int second = Integer.parseInt(z.substring(12, 14));
                Calendar calendar = Calendar.getInstance();
                calendar.set(year, month, date, hour, minute, second);
                return calendar.getTime();
            } catch (NumberFormatException e) {
                return null;
            }
        } else if (z.length() > 1 && z.charAt(0) == '-') {
            try {
                int offset = Integer.parseInt(z);
                return nextDate(new Date(), offset);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        return null;
    }

    private Date nextDate(Date d, int seconds) {
        return new Date(d.getTime() + (long) seconds * 1000);
    }

    private String dateToZString(Date d) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(d);

        StringBuilder sb = new StringBuilder();
        sb.append(calendar.get(Calendar.YEAR));

        int month = calendar.get(Calendar.MONTH) + 1;
        if (month < 10) sb.append('0');
        sb.append(month);

        int day = calendar.get(Calendar.DAY_OF_MONTH);
        if (day < 10) sb.append('0');
        sb.append(day);

        int hour = calendar.get(Calendar.HOUR_OF_DAY);
        if (hour < 10) sb.append('0');
        sb.append(hour);

        int minute = calendar.get(Calendar.MINUTE);
        if (minute < 10) sb.append('0');
        sb.append(minute);

        int second = calendar.get(Calendar.SECOND);
        if (second < 10) sb.append('0');
        sb.append(second);
        sb.append('Z');

        return sb.toString();
    }
}
