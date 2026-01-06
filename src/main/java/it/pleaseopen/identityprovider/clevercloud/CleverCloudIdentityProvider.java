package it.pleaseopen.identityprovider.clevercloud;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.pleaseopen.identityprovider.clevercloud.OAuth1Helper.AccessToken;
import it.pleaseopen.identityprovider.clevercloud.OAuth1Helper.RequestToken;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.*;
import org.keycloak.broker.provider.util.IdentityBrokerState;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

public class CleverCloudIdentityProvider extends AbstractIdentityProvider<CleverCloudIdentityProviderConfig> implements
    SocialIdentityProvider<CleverCloudIdentityProviderConfig>, ExchangeTokenToIdentityProviderToken {
  String CLEVER_CLOUD_TOKEN_TYPE="clever-cloud";


  protected static final Logger logger = Logger.getLogger(CleverCloudIdentityProvider.class);

  private static final String CLEVER_CLOUD_TOKEN = "token";
  private static final String CLEVER_CLOUD_TOKENSECRET = "secret";


  public CleverCloudIdentityProvider(KeycloakSession session, CleverCloudIdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new Endpoint(session, callback, event, this);
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      String clientId = getConfig().getConfig().get("clientId");
      String clientSecret = getConfig().getConfig().get("clientSecret");
      String callbackUrl = request.getRedirectUri() + "?state=" + request.getState().getEncoded();
      
      OAuth1Helper oauthHelper = new OAuth1Helper(clientId, clientSecret);

      AuthenticationSessionModel authSession = request.getAuthenticationSession();
      authSession.setAuthNote("redirect", callbackUrl);

      final RequestToken requestToken = oauthHelper.getRequestToken(CleverCloudApi.REQUEST_TOKEN_URL, callbackUrl);
      authSession.setAuthNote(CLEVER_CLOUD_TOKEN, requestToken.getToken());
      authSession.setAuthNote(CLEVER_CLOUD_TOKENSECRET, requestToken.getTokenSecret());

      URI authenticationUrl = URI.create(CleverCloudApi.AUTHORIZE_URL + "?oauth_token=" + requestToken.getToken());

      return Response.seeOther(authenticationUrl).build();
    } catch(Exception ex) {
      logger.error("Error during performLogin", ex);
      return Response.serverError().build();
    }
  }

  @Override
  public Response exchangeFromToken(UriInfo uriInfo, EventBuilder builder, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject, MultivaluedMap<String, String> params) {
    String requestedType = params.getFirst(OAuth2Constants.REQUESTED_TOKEN_TYPE);
    if (requestedType != null && !requestedType.equals(CLEVER_CLOUD_TOKEN_TYPE)) {
      return exchangeUnsupportedRequiredType();
    }
    if (!getConfig().isStoreToken()) {
      String brokerId = tokenUserSession.getNote(Details.IDENTITY_PROVIDER);
      if (brokerId == null || !brokerId.equals(getConfig().getAlias())) {
        return exchangeNotLinkedNoStore(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
      }
      return exchangeSessionToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
    } else {
      return exchangeStoredToken(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
    }
  }

  protected Response exchangeStoredToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
    FederatedIdentityModel model = session.users().getFederatedIdentity(authorizedClient.getRealm(), tokenSubject, getConfig().getAlias());
    if (model == null || model.getToken() == null) {
      return exchangeNotLinked(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
    }
    String accessToken = model.getToken();
    if (accessToken == null) {
      model.setToken(null);
      session.users().updateFederatedIdentity(authorizedClient.getRealm(), tokenSubject, model);
      return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
    }
    AccessTokenResponse tokenResponse = new AccessTokenResponse();
    tokenResponse.setToken(accessToken);
    tokenResponse.setIdToken(null);
    tokenResponse.setRefreshToken(null);
    tokenResponse.setRefreshExpiresIn(0);
    tokenResponse.getOtherClaims().clear();
    tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, CLEVER_CLOUD_TOKEN_TYPE);
    tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
    return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
  }

  protected Response exchangeSessionToken(UriInfo uriInfo, ClientModel authorizedClient, UserSessionModel tokenUserSession, UserModel tokenSubject) {
    String accessToken = tokenUserSession.getNote(UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN);
    if (accessToken == null) {
      return exchangeTokenExpired(uriInfo, authorizedClient, tokenUserSession, tokenSubject);
    }
    AccessTokenResponse tokenResponse = new AccessTokenResponse();
    tokenResponse.setToken(accessToken);
    tokenResponse.setIdToken(null);
    tokenResponse.setRefreshToken(null);
    tokenResponse.setRefreshExpiresIn(0);
    tokenResponse.getOtherClaims().clear();
    tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, CLEVER_CLOUD_TOKEN_TYPE);
    tokenResponse.getOtherClaims().put(ACCOUNT_LINK_URL, getLinkingUrl(uriInfo, authorizedClient, tokenUserSession));
    return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
  }


  protected static class Endpoint {
    protected final RealmModel realm;
    protected final AuthenticationCallback callback;
    protected final EventBuilder event;
    protected final KeycloakSession session;
    protected final ClientConnection clientConnection;
    protected final HttpHeaders headers;
    private final CleverCloudIdentityProvider provider;

    public Endpoint(KeycloakSession session, AuthenticationCallback callback, EventBuilder event, CleverCloudIdentityProvider provider) {
      this.realm = session.getContext().getRealm();
      this.callback = callback;
      this.event = event;
      this.session = session;
      this.provider = provider;
      this.clientConnection = session.getContext().getConnection();
      this.headers = session.getContext().getRequestHeaders();
    }


    @GET
    @Path("/")
    public Response authResponse(@QueryParam("state") String state,
                                 @QueryParam("denied") String denied,
                                 @QueryParam("oauth_token") String oauthToken,
                                 @QueryParam("user") String user,
                                 @QueryParam("oauth_verifier") String verifier) {
      IdentityBrokerState idpState = IdentityBrokerState.encoded(state, realm);
      String clientId = idpState.getClientId();
      String tabId = idpState.getTabId();
      if (clientId == null || tabId == null) {
        logger.errorf("Invalid state parameter: %s", state);
        sendErrorEvent();
        return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
      }
      ClientModel client = realm.getClientByClientId(clientId);
      AuthenticationSessionModel authSession = ClientSessionCode.getClientSession(state, tabId, session, realm, client, event, AuthenticationSessionModel.class);
      String cleverCloudToken = authSession.getAuthNote(CLEVER_CLOUD_TOKEN);
      String cleverCloudTokenSecret = authSession.getAuthNote(CLEVER_CLOUD_TOKENSECRET);
      String redirect = authSession.getAuthNote("redirect");

      try {
        if (denied != null) {
          return callback.error(this.provider.session.identityProviders().getById("clevercloud"), "Cancelled");
        }
        
        String oauthClientId = provider.getConfig().getConfig().get("clientId");
        String oauthClientSecret = provider.getConfig().getConfig().get("clientSecret");
        OAuth1Helper oauthHelper = new OAuth1Helper(oauthClientId, oauthClientSecret);
        
        RequestToken requestToken = new RequestToken(cleverCloudToken, cleverCloudTokenSecret);
        final AccessToken accessToken = oauthHelper.getAccessToken(CleverCloudApi.ACCESS_TOKEN_URL, requestToken, verifier);

        String userInfoResponse = oauthHelper.executeSignedRequest(CleverCloudApi.USER_INFO_URL, accessToken);
        
        Map<String, Object> userInfo = new ObjectMapper().readValue(userInfoResponse, HashMap.class);
        
        // Extract user ID and create identity context
        String userId = (String) userInfo.get("id");
        BrokeredIdentityContext identity = new BrokeredIdentityContext(userId, provider.getConfig());
        identity.setAuthenticationSession(authSession);
        identity.setIdp(provider);
        
        // Map user attributes from Clever Cloud API
        String email = (String) userInfo.get("email");
        String name = (String) userInfo.get("name");
        Boolean admin = (Boolean) userInfo.get("admin");
        String preferredMFA = (String) userInfo.get("preferredMFA");
        
        identity.setEmail(email);
        identity.setUsername(email); // Use email as username if no specific username field
        
        // Set name components if available
        if (name != null && !name.isEmpty()) {
            // Try to split name into first/last name
            String[] nameParts = name.split("\\s+", 2);
            if (nameParts.length > 0) {
                identity.setFirstName(nameParts[0]);
            }
            if (nameParts.length > 1) {
                identity.setLastName(nameParts[1]);
            }
            identity.setName(name);
        }
        
        // Store additional attributes
        if (admin != null) {
            identity.setUserAttribute("clevercloud.admin", String.valueOf(admin));
        }
        if (preferredMFA != null) {
            identity.setUserAttribute("clevercloud.preferredMFA", preferredMFA);
        }
        
        // Store raw user info for reference
        identity.setUserAttribute("clevercloud.userId", userId);
        
        StringBuilder tokenBuilder = new StringBuilder();
        tokenBuilder.append("{");
        tokenBuilder.append("\"oauth_token\":").append("\"").append(accessToken.getToken()).append("\"").append(",");
        tokenBuilder.append("\"oauth_token_secret\":").append("\"").append(accessToken.getTokenSecret()).append("\"").append(",");
        tokenBuilder.append("\"user_id\":").append("\"").append(user).append("\"");
        tokenBuilder.append("}");
        String token = tokenBuilder.toString();
        
        // Store token if configured (default to false if not set)
        Boolean storeToken = provider.getConfig().isStoreToken();
        if (storeToken != null && storeToken) {
          identity.setToken(token);
        }
        identity.getContextData().put(UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN, token);

        return callback.authenticated(identity);

      } catch(Exception ex) {
        logger.error("Couldn't get user profile from Clever-cloud.", ex);
        sendErrorEvent();
        return ErrorPage.error(session, authSession, Response.Status.BAD_GATEWAY, Messages.UNEXPECTED_ERROR_HANDLING_RESPONSE);
      }
    }

    private void sendErrorEvent() {
      event.event(EventType.LOGIN);
      event.error("clever-cloud_login_failed");
    }

  }

  @Override
  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
    return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
  }

  @Override
  public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
    authSession.setUserSessionNote(UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(UserAuthenticationIdentityProvider.FEDERATED_ACCESS_TOKEN));

  }
}
