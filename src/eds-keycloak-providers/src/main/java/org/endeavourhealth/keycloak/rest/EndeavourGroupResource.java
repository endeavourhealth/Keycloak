package org.endeavourhealth.keycloak.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import java.util.List;

public class EndeavourGroupResource {
    public EndeavourGroupResource(RealmModel realm, KeycloakSession session, AdminPermissionEvaluator auth) {
        this.realm = realm;
        this.auth = auth;
        this.session = session;
    }

    private KeycloakSession session;
    private RealmModel realm;
    private AdminPermissionEvaluator auth;

    @GET
    @NoCache
    @Produces({"application/json"})
    public List<GroupRepresentation> getGroups() {
        this.auth.realm().requireViewAuthorization();
        return ModelToRepresentation.toGroupHierarchy(this.realm, true);
    }
}
