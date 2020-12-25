package org.mk.moqui.authentication

import groovy.transform.CompileStatic
import org.pac4j.core.context.WebContext
import org.pac4j.core.logout.handler.DefaultLogoutHandler

@CompileStatic
class MyLogoutHandler extends DefaultLogoutHandler<WebContext> {
    /**
     * 克服新的浏览器默认cookie的samesite是lax的问题，cas服务器的jsonp调用不会传回sessionid，必须用和后端调用一样的方式。
     * @param context
     * @param key
     */
    @Override
    void destroySessionFront(WebContext context, String key) {
        super.destroySessionBack(context, key)
    }
}
