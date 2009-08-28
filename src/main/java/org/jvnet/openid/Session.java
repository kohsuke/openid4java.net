package org.jvnet.openid;

import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.server.ServerManager;

import java.io.IOException;
import java.net.URL;

/**
 * @author Kohsuke Kawaguchi
 */
public class Session {
    public final Provider provider;
    private final ServerManager manager;

    private ParameterList requestp;
    private boolean authenticatedAndApproved;
    private String mode;
    public String realm;
    public String returnTo;
    private String identity;

    public Session(Provider provider) {
        this.provider = provider;
        this.manager = provider.manager;
    }

    public HttpResponse doEntryPoint(StaplerRequest request) throws IOException {
        requestp = new ParameterList(request.getParameterMap());
        mode = requestp.getParameterValue("openid.mode");
        realm =requestp.getParameterValue("openid.realm");
        returnTo =requestp.getParameterValue("openid.return_to");

        if (realm==null)
            realm = new URL(returnTo).getHost();

        return handleRequest();
    }

    private HttpResponse handleRequest() {
        Message responsem;

        if ("associate".equals(mode)) {
            // --- process an association request ---
            return new MessageResponse(manager.associationResponse(requestp));
        } else
        if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
            // interact with the user and obtain data needed to continue
            if (!authenticatedAndApproved)
                return new HttpRedirect("confirm");

            // --- process an authentication request ---
            responsem = manager.authResponse(requestp, null, identity, true);

            return new HttpRedirect(responsem.getDestinationUrl(true));
        } else if ("check_authentication".equals(mode)) {
            // --- processing a verification request ---
            return new MessageResponse(manager.verify(requestp));
        } else {
            throw new OperationFailure("Unknown request: "+mode);
        }
    }

    public HttpResponse doAuthenticate() {
        // TODO: check the username and password
        authenticatedAndApproved = true;
        identity = provider.address+"?id=username";

        return handleRequest();
    }

    public void doLogout(StaplerRequest req) {
        req.getSession().invalidate();
    }
}
