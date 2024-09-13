package it.pleaseopen.identityprovider.clevercloud;

import com.github.scribejava.core.builder.api.DefaultApi10a;

public class CleverCloudApi extends DefaultApi10a {
    private static final String AUTHORIZE_URL = "api.clever-cloud.com/v2/oauth/authorize";
    private static final String REQUEST_TOKEN_RESOURCE = "api.clever-cloud.com/v2/oauth/request_token";
    private static final String ACCESS_TOKEN_RESOURCE = "api.clever-cloud.com/v2/oauth/access_token";

    protected CleverCloudApi()  {
    }

    private static class InstanceHolder {
        private static final CleverCloudApi INSTANCE = new CleverCloudApi();
    }

    public static CleverCloudApi instance() {
        return InstanceHolder.INSTANCE;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return "https://" + ACCESS_TOKEN_RESOURCE;
    }

    @Override
    public String getRequestTokenEndpoint() {
        return "https://" + REQUEST_TOKEN_RESOURCE;
    }

    @Override
    public String getAuthorizationBaseUrl() {
        return "https://" + AUTHORIZE_URL;
    }

    public static class Authenticate extends CleverCloudApi {

        private static final String AUTHENTICATE_URL = "https://api.clever-cloud.com/v2/oauth/authenticate";

        private Authenticate() {
        }

        private static class InstanceHolder {
            private static final Authenticate INSTANCE = new Authenticate();
        }

        public static Authenticate instance() {
            return InstanceHolder.INSTANCE;
        }

        @Override
        public String getAuthorizationBaseUrl() {
            return AUTHENTICATE_URL;
        }
    }
}
