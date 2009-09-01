#!/bin/bash
cd /home/kohsuke/openid.java.net
exec /usr/java6/bin/java -DURL=http://wsinterop.sun.com:58082/ -jar jetty.jar --log access.log --port 58082 --path / openid-provider.war
