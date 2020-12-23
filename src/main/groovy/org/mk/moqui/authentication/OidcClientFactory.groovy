package org.mk.moqui.authentication

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Requirement
import org.moqui.entity.EntityFacade
import org.pac4j.core.client.Client
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration

class OidcClientFactory implements AuthenticationClientFactory{

    List<Client> buildClients(EntityFacade ef) {
        def enabledIds = ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .list()
                .collect { entity -> entity.clientId as String }
        def clients = ef
                .find('mk.authentication.OidcAuthenticationClient')
                .list()
                .findAll {it.clientId in enabledIds }
                .collect { entity ->
                    OidcConfiguration config = new OidcConfiguration()
                    config.setDiscoveryURI(entity.discoveryUri)
                    config.setClientId(entity.id)
                    config.setSecret(entity.secret)
                    if (entity.preferredJwsAlgorithm) {
                        config.setPreferredJwsAlgorithm(new JWSAlgorithm(entity.preferredJwsAlgorithm, Requirement.RECOMMENDED))
                    }
                    config.setUseNonce(entity.useNonce == 'Y')
                    def client = new OidcClient(config)
                    client.setName(entity.clientId)
                    return client
                }
        return clients
    }
}
