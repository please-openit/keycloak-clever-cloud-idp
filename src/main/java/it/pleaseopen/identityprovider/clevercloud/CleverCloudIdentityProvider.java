package it.pleaseopen.identityprovider.clevercloud;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuth1RequestToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth10aService;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ExchangeTokenToIdentityProviderToken;
import org.keycloak.broker.provider.IdentityProvider;
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


import java.net.URI;
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
      final OAuth10aService service = new ServiceBuilder(getConfig().getConfig().get("clientId"))
              .apiSecret(getConfig().getConfig().get("clientSecret"))
              .callback(request.getRedirectUri() + "?state=" + request.getState().getEncoded())
              .build(CleverCloudApi.instance());

      AuthenticationSessionModel authSession = request.getAuthenticationSession();
      authSession.setAuthNote("redirect", request.getRedirectUri() + "?state=" + request.getState().getEncoded());

      final OAuth1RequestToken requestToken = service.getRequestToken();
      authSession.setAuthNote(CLEVER_CLOUD_TOKEN, requestToken.getToken());
      authSession.setAuthNote(CLEVER_CLOUD_TOKENSECRET, requestToken.getTokenSecret());

      URI authenticationUrl = URI.create(service.getAuthorizationUrl(requestToken));

      return Response.seeOther(authenticationUrl).build();
    }catch(Exception ex){
      ex.printStackTrace();
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
    String accessToken = tokenUserSession.getNote(IdentityProvider.FEDERATED_ACCESS_TOKEN);
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
          return callback.error("Cancelled");
        }
        final OAuth10aService service = new ServiceBuilder(provider.getConfig().getConfig().get("clientId"))
                .apiSecret(provider.getConfig().getConfig().get("clientSecret"))
                .callback(redirect)
                .build(CleverCloudApi.instance());
        OAuth1RequestToken oAuth1RequestToken = new OAuth1RequestToken(cleverCloudToken, cleverCloudTokenSecret);
        final OAuth1AccessToken accessToken = service.getAccessToken(oAuth1RequestToken, verifier);

        final OAuthRequest request2 = new OAuthRequest(Verb.GET, "https://api.clever-cloud.com/v2/self");
        service.signRequest(accessToken, request2);
        try (com.github.scribejava.core.model.Response response = service.execute(request2)) {
          Map<String, String> mapping = new ObjectMapper().readValue(response.getBody(), HashMap.class);
          BrokeredIdentityContext identity = new BrokeredIdentityContext(mapping.get("id"), provider.getConfig() );
          //identity.setIdpConfig(provider.getConfig());
          identity.setAuthenticationSession(authSession);
          identity.setIdp(provider);
          identity.setUsername(mapping.get("email"));
          identity.setEmail(mapping.get("email"));
          StringBuilder tokenBuilder = new StringBuilder();

          tokenBuilder.append("{");
          tokenBuilder.append("\"oauth_token\":").append("\"").append(cleverCloudToken).append("\"").append(",");
          tokenBuilder.append("\"oauth_token_secret\":").append("\"").append(cleverCloudTokenSecret).append("\"").append(",");
          tokenBuilder.append("\"user_id\":").append("\"").append(user).append("\"");
          tokenBuilder.append("}");
          String token = tokenBuilder.toString();
          if (provider.getConfig().isStoreToken()) {
            identity.setToken(token);
          }
          identity.getContextData().put(IdentityProvider.FEDERATED_ACCESS_TOKEN, token);

          return callback.authenticated(identity);
        }

      }catch(Exception ex){
        ex.printStackTrace();
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
    authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));

  }
}
