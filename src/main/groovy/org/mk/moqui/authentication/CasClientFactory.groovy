package org.mk.moqui.authentication

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Requirement
import org.moqui.entity.EntityFacade
import org.pac4j.cas.client.CasClient
import org.pac4j.cas.config.CasConfiguration
import org.pac4j.core.client.Client
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration

class CasClientFactory implements AuthenticationClientFactory{

    List<Client> buildClients(EntityFacade ef) {
        def enabledIds = ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .list()
                .collect { entity -> entity.clientId as String }
        def clients = ef
                .find('mk.authentication.CasAuthenticationClient')
                .list()
                .findAll {it.clientId in enabledIds }
                .collect { entity ->
                    CasConfiguration config = new CasConfiguration()
                    config.setLoginUrl(entity.loginUrl)
                    config.setPrefixUrl(entity.prefixUrl)
                    def client = new CasClient(config)
                    client.setName(entity.clientId)
                    return client
                }
        return clients
    }
}
