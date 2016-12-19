package io.fabric8.maven.docker.access.ecr;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.util.EntityUtils;

/**
 * The state of an aws sigV4 request.
 *
 * @author chas
 * @since 2016-12-9
 */
public class AwsSigner4Request {

    static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");

    static {
        TimeZone utc = TimeZone.getTimeZone("GMT");
        TIME_FORMAT.setTimeZone(utc);
    }

    private static final byte[] EMPTY_BYTES = new byte[0];

    private final String region;
    private final String service;
    private final HttpRequest request;

    private final String signingDate;
    private final String signingDateTime;
    private final String scope;

    private final String method;
    private final URI uri;
    private final String canonicalHeaders;
    private final String signedHeaders;

    AwsSigner4Request(String region, String service, HttpRequest request, Date signingTime) {
        this.region = region;
        this.service = service;
        this.request = request;

        signingDateTime = getSigningDateTime(request, signingTime);
        signingDate = signingDateTime.substring(0, 8);
        scope = signingDate + '/' + region + '/' + service + "/aws4_request";
        method = request.getRequestLine().getMethod();
        uri = getUri(request);


        String[] headers  = canonicalizeHeaders(request);
        canonicalHeaders = headers[0];
        signedHeaders = headers[1];
    }

    public String getRegion() {
        return region;
    }

    public String getService() {
        return service;
    }

    public String getSigningDate() {
        return signingDate;
    }

    public String getSigningDateTime() {
        return signingDateTime;
    }

    public String getScope() {
        return scope;
    }

    public String getMethod() {
        return method;
    }

    public URI getUri() {
        return uri;
    }

    public String getCanonicalHeaders() {
        return canonicalHeaders;
    }

    public String getSignedHeaders() {
        return signedHeaders;
    }

    private static String getSigningDateTime(HttpRequest request, Date signingTime) {
        Header dateHeader = request.getFirstHeader("X-Amz-Date");
        if(dateHeader!=null) {
            return dateHeader.getValue();
        }
        synchronized (TIME_FORMAT) {
            return TIME_FORMAT.format(signingTime);
        }
    }

    private static URI getUri(HttpRequest request) {
        String hostName = request.getFirstHeader("host").getValue();
        String requestTarget = request.getRequestLine().getUri();
        URI requestUri = createUri(hostName, requestTarget);
        return requestUri.normalize();
    }

    private static URI createUri(String authority, String uri) {
        String scheme = "https";
        int schemeEnd = uri.indexOf(':');
        int pathStart = uri.indexOf('/');
        if(schemeEnd>=0 && schemeEnd < pathStart) {
            scheme = uri.substring(0, schemeEnd);
            if(uri.charAt(pathStart + 1) == '/') {
                authority = uri.substring(pathStart);
                pathStart = uri.indexOf('/', pathStart+2);
            }
        }

        String path;
        String query;
        int queryIdx = uri.indexOf('?', pathStart);
        if(queryIdx<0) {
            query =  null;
            path = uri.substring(pathStart);
        }
        else {
            query = uri.substring(queryIdx+1);
            path = uri.substring(pathStart, queryIdx);
        }
        try {
            return new URI(scheme, authority, path, query, null);
        }
        catch(URISyntaxException e) {
            throw new UndeclaredThrowableException(e);
        }
    }

    private static String[] canonicalizeHeaders(HttpRequest request) {
        Map<String, List<String>> unique = new TreeMap<>();
        for (Header header : request.getAllHeaders()) {
            String key = header.getName().toLowerCase(Locale.US);
            if (key.equals("connection")) {
                continue;
            }
            String value = header.getValue();
            if (value != null) {
                List<String> values = unique.get(key);
                if (values == null) {
                    values = new ArrayList<>();
                    unique.put(key, values);
                }
                values.add(value);
            }
        }

        StringBuilder canonical = new StringBuilder();
        for (Map.Entry<String, List<String>> header : unique.entrySet()) {
            // HTTP Header names never contain white-space
            canonical.append(header.getKey());
            canonical.append(':');
            canonical.append(StringUtils.join(header.getValue(), ",").replaceAll("\\s+", " ").trim());
            canonical.append('\n');
        }
        return new String[] { canonical.toString(), StringUtils.join(unique.keySet(),";") };
    }

    byte[] getBytes() {
        if (request instanceof HttpEntityEnclosingRequestBase) {
            try {
                HttpEntity entity = ((HttpEntityEnclosingRequestBase)request).getEntity();
                return EntityUtils.toByteArray(entity);
            } catch (IOException e) {
                throw new UndeclaredThrowableException(e);
            }
        }
        return EMPTY_BYTES;
    }
}
