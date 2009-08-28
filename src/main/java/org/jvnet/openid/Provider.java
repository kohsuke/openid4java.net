package org.jvnet.openid;

import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerProxy;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.ServerManager;

import javax.servlet.http.HttpSession;

/**
 * Open ID provider for java.net
 *
 * @author Kohsuke Kawaguchi
 */
public class Provider implements StaplerProxy {
    final ServerManager manager =new ServerManager();
    /**
     * The URL of this endpoint, like "http://foo:8080/"
     */
    public final String address;

    public Provider(String address) {
        this.address = address;
        manager.setSharedAssociations(new InMemoryServerAssociationStore());
        manager.setPrivateAssociations(new InMemoryServerAssociationStore());
        manager.setOPEndpointUrl(address+"entryPoint");
    }

    public Session getTarget() {
        HttpSession hs = Stapler.getCurrentRequest().getSession();
        Session o = (Session) hs.getAttribute("session");
        if (o==null)
            hs.setAttribute("session",o=new Session(this));
        return o;
    }
}
