package org.jvnet.openid;

import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebResponse;
import org.cyberneko.html.parsers.SAXParser;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.kohsuke.jnt.JavaNet;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.server.ServerManager;
import org.xml.sax.SAXException;

import javax.servlet.ServletException;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

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
     * Binds client to URL.
     */
    public Client getClient() {
        return provider.client;
    }

    public String getJavanetId() {
        return javanetId;
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
                if (!approvedRealms.contains(realm)) {
                    /* get the confirmation from the user before we proceed.

                        This flow goes as follows:

                        1. browser is redirected to https://openid4javanet.dev.java.net/nonav/session.html
                        2. session.html extracts a session ID and redirect it back to
                           http://ourserver/authenticate?session=JSESSIONID
                        3.
                    */
                    return new HttpRedirect(provider.sessionRetrieverUrl);
                }


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
    public HttpResponse doAuthenticate(@QueryParameter String session) throws IOException, SAXException, DocumentException {
        if (session==null)
            throw new Error("No session ID specified");

        JavaNet con = JavaNet.connectAnonymously();
        WebConversation wc = con.getConversation();
        wc.addCookie("JSESSIONID",session);
        WebResponse rsp = wc.getResponse("https://www.dev.java.net/servlets/StartPage");
        Document dom = new SAXReader(new SAXParser()).read(new StringReader(rsp.getText()));
        Element name = (Element) dom.selectSingleNode("//STRONG[@class='username']");
        if (name!=null) {// found the ID
            this.javanetId = name.getTextTrim();
            return new HttpRedirect("confirm");
        }

        // not logged in yet. have the user login and come back
        return new HttpRedirect("https://www.dev.java.net/servlets/TLogin?detour="+ provider.sessionRetrieverUrl);
    }

    public HttpResponse doVerify() {
        approvedRealms.add(realm);
        identity = provider.address+"~"+javanetId;

        return handleRequest();
    }

    /**
     * Invalidates this session.
     */
    public void doLogout(StaplerRequest req) {
        req.getSession().invalidate();
    }

    public void doDynamic(StaplerRequest req, StaplerResponse rsp) throws IOException, ServletException {
        if (req.getRestOfPath().startsWith("/~"))
            req.getView(this,"xrds.jelly").forward(req,rsp);
        else
            rsp.sendError(404);
    }
}
