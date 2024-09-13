package it.pleaseopen.identityprovider.clevercloud;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

public class CleverCloudIdentityProviderFactory extends AbstractIdentityProviderFactory<CleverCloudIdentityProvider> implements IdentityProviderFactory<CleverCloudIdentityProvider> {

  public static final String PROVIDER_ID = "clevercloud";
  public static final String PROVIDER_NAME = "Clever Cloud";

  @Override
  public String getName() {
    return PROVIDER_NAME;
  }

  @Override
  public CleverCloudIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new CleverCloudIdentityProvider(session, new CleverCloudIdentityProviderConfig(model));
  }

  @Override
  public CleverCloudIdentityProviderConfig createConfig() {
    return new CleverCloudIdentityProviderConfig();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
