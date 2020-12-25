package org.mk.moqui.authentication

import groovy.transform.CompileStatic
import org.moqui.context.ExecutionContext
import org.moqui.entity.EntityFacade
import org.pac4j.core.authorization.authorizer.DefaultAuthorizers
import org.pac4j.core.client.Client
import org.pac4j.core.config.Config
import org.pac4j.core.context.JEEContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.JEESessionStore
import org.pac4j.core.engine.DefaultCallbackLogic
import org.pac4j.core.engine.DefaultLogoutLogic
import org.pac4j.core.engine.DefaultSecurityLogic
import org.pac4j.core.engine.SecurityGrantedAccessAdapter
import org.pac4j.core.http.adapter.JEEHttpActionAdapter
import org.pac4j.core.profile.UserProfile
import org.pac4j.core.profile.factory.ProfileManagerFactory

@CompileStatic
class Login {
    static final JEESessionStore sessionStore = new JEESessionStore()

    static Config globalConfig
    static List<AuthenticationClientFactory> clientFactories = [
            new CasClientFactory() as AuthenticationClientFactory,
            new OidcClientFactory() as AuthenticationClientFactory
    ]

    static List<Client> getClients(EntityFacade ef) {
        List<List<Client>> list = clientFactories.collect({ factory -> factory.buildClients(ef) })
        return list.flatten() as List<Client>
    }

    static Config getConfig(ExecutionContext ec) {
        return new Config("${getMoquiUrl(ec)}/Login/callback", getClients(ec.entity))
    }

    static List<String> getEnabledClients(EntityFacade ef) {
        return ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .list()
                .collect { entity -> entity.clientId as String }
    }

    static JEEContext buildContext(ExecutionContext ec) {
        def request = ec.getWeb().getRequest()
        def response = ec.getWeb().getResponse()

        return new JEEContext(request, response, sessionStore)
    }

    static String getMoquiUrl(ExecutionContext ec) {
        return ec.web.getWebappRootUrl(true, true)
    }

    static ProfileManagerFactory getProfileManagerFactory(ExecutionContext ec) {
        return { WebContext ctx -> new MoquiProfileManager(ctx, ec) } as ProfileManagerFactory
    }

    static login(ExecutionContext ec) {
        def disabled = ec.artifactExecution.disableAuthz()
        def logger = ec.getLogger()

        DefaultSecurityLogic logic = new DefaultSecurityLogic()
        logic.setProfileManagerFactory(getProfileManagerFactory(ec))

        def clients = getEnabledClients(ec.entity)
        if (clients.size() < 1) {
            ec.logger.warn('No identity clients configured for moqui-pac4j-authentication')
            errorRedirect(ec)
            return
        }

        try {
            def result = logic.perform(
                    buildContext(ec),
                    getConfig(ec),
                    new MoquiAccessGrantedAdapter(),
                    JEEHttpActionAdapter.INSTANCE,
                    clients.join(','),
                    DefaultAuthorizers.IS_AUTHENTICATED,
                    '',
                    false
            )
        }
        catch (Exception e) {
            ec.logger.log(200, "Encounter login error", e)
            errorRedirect(ec)
        } finally {
            if (!disabled) {
                ec.artifactExecution.enableAuthz()
            }
        }
    }

    // Called when there is an error to redirect the user to /login/local
    static void errorRedirect(ExecutionContext ec) {
        if (!ec.web.response.isCommitted()) {
            ec.logger.warn('Encountered login error, redirecting to /Login/Local')
            ec.web.response.sendRedirect('/Login/Local')
        }
    }

    static void callback(ExecutionContext ec) {
        def disabled = ec.artifactExecution.disableAuthz()
        def logger = ec.getLogger()
        def context = buildContext(ec)

        DefaultCallbackLogic callback = new DefaultCallbackLogic()
        callback.setProfileManagerFactory(getProfileManagerFactory(ec))
        try {
            def result = callback.perform(
                    context,
                    getConfig(ec),
                    JEEHttpActionAdapter.INSTANCE,
                    null,
                    true,
                    false,
                    true,
                    getEnabledClients(ec.entity).join(',')
            )
        }
        catch (Exception e) {
            e.printStackTrace()
        } finally {
            if (!disabled) {
                ec.artifactExecution.enableAuthz()
            }
        }
    }

    static void logout(ExecutionContext ec) {
        def disabled = ec.artifactExecution.disableAuthz()
        DefaultLogoutLogic logout = new DefaultLogoutLogic()
        logout.setProfileManagerFactory(getProfileManagerFactory(ec))
        def defaultUrl = "${getMoquiUrl(ec)}/"

        try {
            logout.perform(
                    buildContext(ec),
                    getConfig(ec),
                    JEEHttpActionAdapter.INSTANCE,
                    defaultUrl,
                    '/',
                    true,
                    true,
                    true
            )
        } finally {
            if (!disabled) {
                ec.artifactExecution.enableAuthz()
            }
        }
    }
}

class MoquiAccessGrantedAdapter implements SecurityGrantedAccessAdapter<Object, WebContext> {

    @Override
    Object adapt(WebContext context, Collection<UserProfile> profiles, Object... parameters) throws Exception {
        return null
    }
}
