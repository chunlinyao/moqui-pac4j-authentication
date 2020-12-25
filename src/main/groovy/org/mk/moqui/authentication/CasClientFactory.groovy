package org.mk.moqui.authentication


import groovy.transform.CompileStatic
import org.moqui.entity.EntityFacade
import org.pac4j.cas.client.CasClient
import org.pac4j.cas.config.CasConfiguration
import org.pac4j.cas.logout.DefaultCasLogoutHandler
import org.pac4j.core.client.Client

import java.sql.Timestamp
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap

@CompileStatic
class CasClientFactory implements AuthenticationClientFactory {
    ConcurrentMap<String, ClientEntry> clientMap = new ConcurrentHashMap<>()

    List<Client> buildClients(EntityFacade ef) {
        def enabledIds = ef.find('mk.authentication.AuthenticationClient')
                .condition('enabled', 'Y')
                .useCache(true)
                .list()
                .collect { entity -> entity.clientId as String }
        ef.find('mk.authentication.CasAuthenticationClient')
                .useCache(true)
                .list()
                .each { entity ->
                    if (entity.clientId in enabledIds) {
                        clientMap.compute(entity.clientId as String, { k, v ->
                            if (v == null || v.lastUpdatedStamp != entity.lastUpdatedStamp) {
                                CasConfiguration config = new CasConfiguration()
                                def handler = new DefaultCasLogoutHandler()
                                handler.setDestroySession(true)
                                config.setLogoutHandler(handler)
                                config.setLoginUrl(entity.loginUrl as String)
                                config.setPrefixUrl(entity.prefixUrl as String)
                                Client client = new CasClient(config)
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
