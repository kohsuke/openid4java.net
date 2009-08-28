package org.jvnet.openid;

import org.kohsuke.jnt.JavaNet;
import org.kohsuke.jnt.ProcessingException;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.openid4java.message.Message;
import org.openid4java.message.ParameterList;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.MessageException;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.server.ServerManager;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import java.util.Set;
import java.util.HashSet;
import java.util.Map;

/**
 * Session-scoped object that serves the top page.
 *
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

    /**
     * Landing page for the OpenID protocol.
     */
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
        try {
            if ("associate".equals(mode)) {
                // --- process an association request ---
                return new MessageResponse(manager.associationResponse(requestp));
            } else
            if ("checkid_setup".equals(mode) || "checkid_immediate".equals(mode)) {
                if (!approvedRealms.contains(realm))
                    // get the confirmation from the user before we proceed
                    return new HttpRedirect("confirm");


                Message rsp = manager.authResponse(requestp, identity, identity, true);
                respondToFetchRequest(rsp);

                return new HttpRedirect(rsp.getDestinationUrl(true));
            } else if ("check_authentication".equals(mode)) {
                return new MessageResponse(manager.verify(requestp));
            } else {
                throw new OperationFailure("Unknown request: "+mode);
            }
        } catch (MessageException e) {
            e.printStackTrace();
            throw new OperationFailure(e.getMessage());
        }
    }

    /**
     * Responds to the fetch request by adding them.
     *
     * Java.net only gives us the ID, and everything else is just mechanically derived from it,
     * so there's no need to get the confirmation from users for passing them.
     */
    private void respondToFetchRequest(Message rsp) throws MessageException {
        AuthRequest authReq = AuthRequest.createAuthRequest(requestp, manager.getRealmVerifier());
        if (authReq.hasExtension(AxMessage.OPENID_NS_AX)) {
            MessageExtension ext = authReq.getExtension(AxMessage.OPENID_NS_AX);
            if (ext instanceof FetchRequest) {
                FetchRequest fetchReq = (FetchRequest) ext;
                FetchResponse fr = FetchResponse.createFetchResponse();

                for (Map.Entry<String,String> e : ((Map<String,String>)fetchReq.getAttributes()).entrySet()) {
                    if (e.getValue().equals("http://axschema.org/contact/email")
                    ||  e.getValue().equals("http://schema.openid.net/contact/email"))
                        fr.addAttribute(e.getKey(),e.getValue(),javanetId+"@dev.java.net");
                    if (e.getValue().equals("http://axschema.org/namePerson/friendly"))
                        fr.addAttribute(e.getKey(),e.getValue(),javanetId);

                }

                rsp.addExtension(fr);
            }
        }
    }

    /**
     * Accepts a submission of credential from the user,
     * and continues the OpenID protocol.
     */
    public HttpResponse doAuthenticate(StaplerRequest req, @QueryParameter String username, @QueryParameter String password) {
        if (this.javanetId==null) {
            try {
                if (System.getProperty("skip")==null)
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

    /**
     * Invalidates this session.
     */
    public void doLogout(StaplerRequest req) {
        req.getSession().invalidate();
    }
}
