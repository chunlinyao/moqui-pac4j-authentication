package org.mk.moqui.authentication

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.Requirement
import groovy.transform.CompileStatic
import org.moqui.entity.EntityFacade
import org.pac4j.core.client.Client
import org.pac4j.oidc.client.OidcClient
import org.pac4j.oidc.config.OidcConfiguration

import java.sql.Timestamp
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap

@CompileStatic
class OidcClientFactory implements AuthenticationClientFactory {

    ConcurrentMap<String, ClientEntry> clientMap = new ConcurrentHashMap<>()

    List<Client> buildClients(EntityFacade ef) {
        def enabledIds = ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .useCache(true)
                .list()
                .collect { entity -> entity.clientId as String }
        def clients = ef
                .find('mk.authentication.OidcAuthenticationClient')
                .useCache(true)
                .list()
                .collect { entity ->
                    if (entity.clientId in enabledIds) {
                        clientMap.compute(entity.clientId as String, { k, v ->
                            if (v == null || v != entity.lastUpdatedStamp) {
                                OidcConfiguration config = new OidcConfiguration()
                                config.setDiscoveryURI(entity.discoveryUri as String)
                                config.setClientId(entity.id as String)
                                config.setSecret(entity.secret as String)
                                if (entity.preferredJwsAlgorithm) {
                                    config.setPreferredJwsAlgorithm(new JWSAlgorithm(entity.preferredJwsAlgorithm as String, Requirement.RECOMMENDED))
                                }
                                config.setUseNonce(entity.useNonce == 'Y')
                                def client = new OidcClient(config)
                                client.setName(entity.clientId as String)
                                return new ClientEntry(client: client, lastUpdatedStamp: entity.lastUpdatedStamp as Timestamp)
                            } else {
                                return v
                            }
                        })
                    } else {
                        clientMap.remove(entity.clientId)
                    }
                }
        return clientMap.collect { it.value.client }
    }
}
