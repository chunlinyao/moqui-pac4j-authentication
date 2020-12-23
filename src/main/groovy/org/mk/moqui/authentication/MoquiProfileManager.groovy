package org.mk.moqui.authentication

import org.moqui.impl.context.ExecutionContextFactoryImpl
import org.moqui.impl.context.ExecutionContextImpl
import org.moqui.impl.context.UserFacadeImpl
import org.moqui.impl.util.MoquiShiroRealm
import org.moqui.context.ExecutionContext
import org.pac4j.cas.profile.CasProfile
import org.pac4j.core.context.WebContext
import org.pac4j.core.profile.CommonProfile
import org.pac4j.core.profile.ProfileManager

import javax.naming.AuthenticationException

/**
 * Creates and registers a subject with the moqui SecurityManager
 */
class MoquiProfileManager extends ProfileManager<CommonProfile> {
    ExecutionContext ec
    MoquiProfileManager(WebContext context, ExecutionContext ec) {
        super(context)
        this.ec = ec
    }

    @Override
    void save(final boolean saveInSession, final CommonProfile profile, final boolean multiProfile) {
        super.save(saveInSession, profile, multiProfile)

        try {
            // TODO: Make username/email configurable
            Object username = getUserName(profile)
            ((UserFacadeImpl) ec.user).internalLoginUser(username)
        } catch (final AuthenticationException e) {
            super.remove(saveInSession)
            throw e
        }
    }

    private Object getUserName(CommonProfile profile) {
        def username = profile.username
        if (!username) {
            username = profile.attributes.get("preferred_username")
        }
        if (!username) {
            username = profile.attributes.get("email")
        }
        if (!username) {
            username = profile.id
        }
        if (!username) {
            ec.logger.error("can not found username from profile.")
        }
        username
    }

    @Override
    void remove(final boolean removeFromSession) {
        super.remove(removeFromSession)

        ec.user.logoutUser()
    }
}