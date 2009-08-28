package org.jvnet.openid;

import org.kohsuke.jnt.JavaNet;
import org.kohsuke.jnt.ProcessingException;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.server.ServerManager;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import java.util.Set;
import java.util.HashSet;

/**
 * @author Kohsuke Kawaguchi
 */
public class Session {
    public final Provider provider;
    private final ServerManager manager;

    private ParameterList requestp;
    /**
     * If this user is already authenticated with java.net, set to the java.net user name.
     */
    private String javanetId;
    private final Set<String> approvedRealms = new HashSet<String>();
    private String mode;
    public String realm;
    public String returnTo;
    private String identity;

    public Session(Provider provider) {
        this.provider = provider;
        this.manager = provider.manager;
    }

    public boolean isAuthenticated() {
        return javanetId !=null;
    }

    public HttpResponse doEntryPoint(StaplerRequest request) throws IOException {
        requestp = new ParameterList(request.getParameterMap());
        mode = requestp.getParameterValue("openid.mode");
        realm = requestp.getParameterValue("openid.realm");
        returnTo = requestp.getParameterValue("openid.return_to");

        if (realm==null && returnTo!=null)
            try {
                realm = new URL(returnTo).getHost();
            } catch (MalformedURLException e) {
                realm = returnTo; // fall back
            }

        return handleRequest();
    }

    private HttpResponse handleRequest() {
        if ("associate".equals(mode)) {
            // --- process an association request ---
            return new MessageResponse(manager.associationResponse(requestp));
        } else
        if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
            if (!approvedRealms.contains(realm))
                // get the confirmation from the user before we proceed
                return new HttpRedirect("confirm");

            Message rsp = manager.authResponse(requestp, identity, null, true);
            return new HttpRedirect(rsp.getDestinationUrl(true));
        } else if ("check_authentication".equals(mode)) {
            return new MessageResponse(manager.verify(requestp));
        } else {
            throw new OperationFailure("Unknown request: "+mode);
        }
    }

    public HttpResponse doAuthenticate(StaplerRequest req, @QueryParameter String username, @QueryParameter String password) {
        if (this.javanetId==null) {
            try {
                JavaNet.connect(username,password);
            } catch (ProcessingException e) {
                // failed to login
                throw new OperationFailure("Failed to login as "+username+" :"+e.getMessage());
            }
            this.javanetId = username;
            // retain this session for a long time, since the user has logged in
            req.getSession().setMaxInactiveInterval((int)TimeUnit.DAYS.toSeconds(14));
        }
        approvedRealms.add(realm);
        identity = provider.address+"?id="+javanetId;

        return handleRequest();
    }

    public void doLogout(StaplerRequest req) {
        req.getSession().invalidate();
    }
}
