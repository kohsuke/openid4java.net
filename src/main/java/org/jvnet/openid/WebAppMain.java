package org.jvnet.openid;

import org.kohsuke.stapler.framework.AbstractWebAppMain;

public class WebAppMain extends AbstractWebAppMain<Provider> {
    public WebAppMain() {
        super(Provider.class);
    }

    protected String getApplicationName() {
        return "OpenIDProvider";
    }

    protected Object createApplication() throws Exception {
        return new Provider(System.getProperty("URL","http://localhost:8080/"));
    }
}