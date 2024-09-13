package it.pleaseopen.identityprovider.clevercloud;

import org.keycloak.models.IdentityProviderModel;

public class CleverCloudIdentityProviderConfig extends IdentityProviderModel {
    public CleverCloudIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public CleverCloudIdentityProviderConfig() {
        super();
    }

    public String getClientId() {
        return getConfig().get("apiKey");
    }
    public void setClientId(String clientId) {
        getConfig().put("apiKey", clientId);
    }

    public String getClientSecret() { return getConfig().get("apiSecret"); }
    public void setClientSecret(String clientSecret) {
        getConfig().put("apiSecret", clientSecret);
    }

    public String getApiKey() {
        return getConfig().get("apiKey");
    }
    public void setApiKey(String apiKey) {
        getConfig().put("apiKey", apiKey);
    }

    public String getApiSecret() { return getConfig().get("apiSecret"); }
    public void setApiSecret(String apiSecret) {
        getConfig().put("apiSecret", apiSecret);
    }


}
