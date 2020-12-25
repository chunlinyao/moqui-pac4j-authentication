package org.mk.moqui.authentication

import groovy.transform.Canonical
import groovy.transform.CompileStatic
import org.pac4j.core.client.Client

import java.sql.Timestamp

@CompileStatic
@Canonical
class ClientEntry {
    Client client
    Timestamp lastUpdatedStamp
}
