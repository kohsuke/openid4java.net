package org.jvnet.openid;

import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;

import javax.servlet.ServletException;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import java.io.IOException;

/**
 * @author Kohsuke Kawaguchi
 */
public class OperationFailure extends RuntimeException implements HttpResponse {
    public OperationFailure(String message) {
        super(message);
    }

    public void generateResponse(StaplerRequest req, StaplerResponse rsp, Object node) throws IOException, ServletException {
        rsp.sendError(SC_INTERNAL_SERVER_ERROR,getMessage());
    }
}
