package it.pleaseopen.identityprovider.clevercloud;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper class for OAuth 1.0a authentication
 * Implements the OAuth 1.0a protocol without external dependencies
 */
public class OAuth1Helper {
    
    protected static final Logger logger = Logger.getLogger(OAuth1Helper.class);
    
    private static final String OAUTH_SIGNATURE_METHOD = "HMAC-SHA1";
    private static final String OAUTH_VERSION = "1.0";
    private static final SecureRandom RANDOM = new SecureRandom();
    
    private final String consumerKey;
    private final String consumerSecret;
    private final HttpClient httpClient;
    
    public OAuth1Helper(String consumerKey, String consumerSecret) {
        this.consumerKey = consumerKey;
        this.consumerSecret = consumerSecret;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }
    
    /**
     * OAuth 1.0a Request Token
     */
    public static class RequestToken {
        private final String token;
        private final String tokenSecret;
        
        public RequestToken(String token, String tokenSecret) {
            this.token = token;
            this.tokenSecret = tokenSecret;
        }
        
        public String getToken() {
            return token;
        }
        
        public String getTokenSecret() {
            return tokenSecret;
        }
    }
    
    /**
     * OAuth 1.0a Access Token
     */
    public static class AccessToken {
        private final String token;
        private final String tokenSecret;
        
        public AccessToken(String token, String tokenSecret) {
            this.token = token;
            this.tokenSecret = tokenSecret;
        }
        
        public String getToken() {
            return token;
        }
        
        public String getTokenSecret() {
            return tokenSecret;
        }
    }
    
    /**
     * Get a request token from the OAuth provider
     */
    public RequestToken getRequestToken(String requestTokenUrl, String callbackUrl) throws IOException, InterruptedException {
        Map<String, String> oauthParams = new HashMap<>();
        oauthParams.put("oauth_callback", callbackUrl);
        oauthParams.put("oauth_consumer_key", consumerKey);
        oauthParams.put("oauth_nonce", generateNonce());
        oauthParams.put("oauth_signature_method", OAUTH_SIGNATURE_METHOD);
        oauthParams.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        oauthParams.put("oauth_version", OAUTH_VERSION);
        
        
        String signature = generateSignature("POST", requestTokenUrl, oauthParams, consumerSecret, "");
        oauthParams.put("oauth_signature", signature);
        
        String authHeader = buildAuthorizationHeader(oauthParams);
                
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(requestTokenUrl))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "Keycloak-CleverCloud/1.0")
                .header("Accept", "*/*")
                .POST(HttpRequest.BodyPublishers.ofString(""))
                .build();
                
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("Failed to get request token: " + response.statusCode() + " - " + response.body());
        }
        
        Map<String, String> params = parseQueryString(response.body());
        return new RequestToken(params.get("oauth_token"), params.get("oauth_token_secret"));
    }
    
    /**
     * Get an access token using the request token and verifier
     */
    public AccessToken getAccessToken(String accessTokenUrl, RequestToken requestToken, String verifier) throws IOException, InterruptedException {
        Map<String, String> oauthParams = new HashMap<>();
        oauthParams.put("oauth_consumer_key", consumerKey);
        oauthParams.put("oauth_nonce", generateNonce());
        oauthParams.put("oauth_signature_method", OAUTH_SIGNATURE_METHOD);
        oauthParams.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        oauthParams.put("oauth_token", requestToken.getToken());
        oauthParams.put("oauth_verifier", verifier);
        oauthParams.put("oauth_version", OAUTH_VERSION);
        
        String signature = generateSignature("POST", accessTokenUrl, oauthParams, consumerSecret, requestToken.getTokenSecret());
        oauthParams.put("oauth_signature", signature);
        
        String authHeader = buildAuthorizationHeader(oauthParams);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(accessTokenUrl))
                .header("Authorization", authHeader)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(""))
                .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("Failed to get access token: " + response.statusCode() + " - " + response.body());
        }
        
        Map<String, String> params = parseQueryString(response.body());
        return new AccessToken(params.get("oauth_token"), params.get("oauth_token_secret"));
    }
    
    /**
     * Execute a signed GET request with the access token
     */
    public String executeSignedRequest(String url, AccessToken accessToken) throws IOException, InterruptedException {
        Map<String, String> oauthParams = new HashMap<>();
        oauthParams.put("oauth_consumer_key", consumerKey);
        oauthParams.put("oauth_nonce", generateNonce());
        oauthParams.put("oauth_signature_method", OAUTH_SIGNATURE_METHOD);
        oauthParams.put("oauth_timestamp", String.valueOf(System.currentTimeMillis() / 1000));
        oauthParams.put("oauth_token", accessToken.getToken());
        oauthParams.put("oauth_version", OAUTH_VERSION);
        
        String signature = generateSignature("GET", url, oauthParams, consumerSecret, accessToken.getTokenSecret());
        oauthParams.put("oauth_signature", signature);
        
        String authHeader = buildAuthorizationHeader(oauthParams);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authHeader)
                .GET()
                .build();
        
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("Failed to execute signed request: " + response.statusCode() + " - " + response.body());
        }
        
        return response.body();
    }
    
    /**
     * Generate OAuth signature
     */
    private String generateSignature(String method, String url, Map<String, String> params, 
                                     String consumerSecret, String tokenSecret) {
        try {
            // Create the signature base string
            String baseString = buildSignatureBaseString(method, url, params);
            
            // Create the signing key
            String signingKey = percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret);
            
            // Generate the signature
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret = new SecretKeySpec(signingKey.getBytes(StandardCharsets.UTF_8), "HmacSHA1");
            mac.init(secret);
            byte[] digest = mac.doFinal(baseString.getBytes(StandardCharsets.UTF_8));
            
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to generate signature", e);
        }
    }
    
    /**
     * Build the signature base string
     */
    private String buildSignatureBaseString(String method, String url, Map<String, String> params) {
        // Normalize URL (remove query parameters if any)
        String normalizedUrl = url.split("\\?")[0];
        
        // Sort and encode parameters
        String paramString = params.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> percentEncode(e.getKey()) + "=" + percentEncode(e.getValue()))
                .collect(Collectors.joining("&"));
        
        return method.toUpperCase() + "&" + percentEncode(normalizedUrl) + "&" + percentEncode(paramString);
    }
    
    /**
     * Build OAuth Authorization header
     * According to RFC 5849, parameter values must be percent-encoded in the header
     */
    private String buildAuthorizationHeader(Map<String, String> oauthParams) {
        String params = oauthParams.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + "=\"" + percentEncode(e.getValue()) + "\"")
                .collect(Collectors.joining(", "));
        
        return "OAuth " + params;
    }
    
    /**
     * Generate a random nonce
     * Matches ScribeJava's TimestampServiceImpl: timestamp + random integer
     * Using absolute value to ensure positive nonce
     */
    private String generateNonce() {
        long timestamp = System.currentTimeMillis() / 1000;
        return String.valueOf(timestamp + Math.abs(RANDOM.nextInt()));
    }
    
    /**
     * Percent encode a string according to OAuth spec
     */
    private String percentEncode(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
    }
    
    /**
     * Parse query string into map
     */
    private Map<String, String> parseQueryString(String queryString) {
        Map<String, String> params = new HashMap<>();
        if (queryString == null || queryString.isEmpty()) {
            return params;
        }
        
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            String[] keyValue = pair.split("=", 2);
            if (keyValue.length == 2) {
                params.put(keyValue[0], keyValue[1]);
            }
        }
        return params;
    }
}
