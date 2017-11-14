package org.endeavourhealth.keycloak.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.permissions.AdminPermissions;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class EndeavourRestResource {

    protected static final ServicesLogger logger = ServicesLogger.LOGGER;   //  LOGGER <----3.0.0.FINAL;

    @Context
    protected UriInfo uriInfo;

    @Context
    protected ClientConnection clientConnection;

	private final KeycloakSession session;
    private final RealmModel realm;
    protected AppAuthManager authManager;

	public EndeavourRestResource(KeycloakSession session) {
		this.session = session;
        this.realm = session.getContext().getRealm();
        this.authManager = new AppAuthManager();
    }

    @GET
    @NoCache
    @Produces({"application/json"})
    public Map<String, Object> getInfo() {
        logger.info("Endeavour Keycloak Services info requested");
        Map<String, Object> info = new HashMap<>();
        info.put("message", "Endeavour REST API resource");
        info.put("timestamp", new Date());
        return info;
    }


    @Path("groups")
    public EndeavourGroupResource getEndeavourGroupResource(@Context final HttpHeaders headers) {
        ResteasyProviderFactory.getInstance().injectProperties(this);
        AdminAuth adminAuth = authenticateRealmAdminRequest(headers);
        AdminPermissionEvaluator realmAuth = AdminPermissions.evaluator(session, realm, adminAuth);
        realmAuth.realm().requireViewRealm();
        return new EndeavourGroupResource(this.realm, this.session, realmAuth);
    }

    protected AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
        String tokenString = authManager.extractAuthorizationHeaderToken(headers);
        if (tokenString == null) throw new NotAuthorizedException("Bearer");
        AccessToken token;
        try {
            JWSInput input = new JWSInput(tokenString);
            token = input.readJsonContent(AccessToken.class);
        } catch (JWSInputException e) {
            throw new NotAuthorizedException("Bearer token format error");
        }
        String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
        RealmManager realmManager = new RealmManager(session);
        RealmModel realm = realmManager.getRealmByName(realmName);
        if (realm == null) {
            throw new NotAuthorizedException("Unknown realm in token");
        }
        AuthenticationManager.AuthResult authResult = authManager.authenticateBearerToken(session, realm, uriInfo, clientConnection, headers);
        if (authResult == null) {
            logger.debug("Token not valid");
            throw new NotAuthorizedException("Bearer");
        }

        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null) {
            throw new NotFoundException("Could not find client for authorization");

        }

        return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
    }

}
