package it.pleaseopen.identityprovider.clevercloud;

/**
 * Configuration class for Clever Cloud OAuth endpoints
 */
public class CleverCloudApi {
    
    public static final String AUTHORIZE_URL = "https://api.clever-cloud.com/v2/oauth/authorize";
    public static final String AUTHENTICATE_URL = "https://api.clever-cloud.com/v2/oauth/authenticate";
    public static final String REQUEST_TOKEN_URL = "https://api.clever-cloud.com/v2/oauth/request_token";
    public static final String ACCESS_TOKEN_URL = "https://api.clever-cloud.com/v2/oauth/access_token";
    public static final String USER_INFO_URL = "https://api.clever-cloud.com/v2/self";
    
    private CleverCloudApi() {
        // Utility class
    }
}
