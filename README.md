# experimental branch

This branch contains **ualpn**, the new transparent proxy with built-in
tls-alpn-01 responder.

The intended use case is **ualpn** listening on port 443 for incoming
HTTPS connections. Most of the time it will just transparently proxy
connections to the real web server (which can be listening on another
machine or another TCP port on the same machine). But when a tls-alpn-01
challenge handshake comes in, **ualpn** handles it on the fly instead of
proxying it to the webserver.

While running **ualpn** also listens to a UNIX domain socket so that it
can be fed the necessary tls-alpn-01 key authorizations for the domains
being validated by the ACME server. **ualpn** was designed to be easy to
integrate with not only **uacme** but also other ACME clients.

# getting started, quick and dirty

* build and install the software
```
git clone -b ualpn https://github.com/ndilieto/uacme
cd uacme
./configure --disable-maintainer-mode --prefix=/usr/local
make && sudo make install
```
* move your real HTTPS server to port 4443 and also enable the PROXY protocol:
  * for nginx: https://docs.nginx.com/nginx/admin-guide/load-balancer/using-proxy-protocol
  * for apache: https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html
* launch ualpn as a daemon and check the logs (by default in syslog)
```
sudo ualpn -v -d -u nobody:nogroup -c 127.0.0.1@4443 -S 666
```
* create an ACME account and try obtaining a certificate with tls-alpn-01 challenge
```
uacme -v -s -c /tmp/uacme.d -y new
uacme -v -s -c /tmp/uacme.d -h /usr/local/share/uacme/ualpn.sh issue www.example.com
```
* for more information check the man pages in the distribution
```
man ualpn
man uacme
```

caveat emptor: **ualpn** is still work in progress and requires GnuTLS (mbedTLS and
OpenSSL are not supported yet). Bug reports and suggestions are welcome.


