<img src="https://repository-images.githubusercontent.com/182530051/6d85b680-8e9d-11e9-91b9-0bc9eefac05e" alt="uacme manual">

# uacme
lightweight client for the [RFC8555](https://tools.ietf.org/html/rfc8555) 
ACMEv2 protocol, written in plain C with minimal dependencies
([libcurl](https://curl.haxx.se/libcurl) and one of
[GnuTLS](https://gnutls.org), [OpenSSL](https://www.openssl.org)
or [mbedTLS](https://tls.mbed.org)). The ACMEv2 protocol allows a 
Certificate Authority ([https://letsencrypt.org](https://letsencrypt.org)
is a popular one) and an applicant to automate the process of 
verification and certificate issuance. The protocol also provides 
facilities for other certificate management functions, such as
certificate revocation.

## Features
* **Written in C** - It runs on any unix machine, including Linux, BSD, ...
* **Minimal dependencies** - Other than the standard C library, **uacme** 
depends only on libcurl and one of GnuTLS, OpenSSL or mbedTLS. It does
all the network communications and crypto without spawning external
processes.  Particularly when using mbedTLS, it is small enough to run
on embedded systems with severe RAM and program memory restrictions
(such as OpenWRT routers, for example).  This is in contrast to
solutions based on python or shell scripts, which may well be a few
hundred lines but are ugly, brittle and also require many
other large applications such as python or openssl to work.
* **Native ECC support** - Elliptic Curve keys and certificates can be
generated with a commmand line option (-t EC)
* **Easily extensible** - It optionally calls an external hook program
with the tokens required for domain authorization by the server. The 
hook program can be an executable, shell script, perl script, python 
script, or any file that the operating system can execute.
* **ACME challenge agnostic** - It provides the user or hook program
with all tokens and information required to complete any challenge type
(including http-01, dns-01 and tls-alpn-01) but leaves the task of setting up 
and cleaning up the challenge environment to the user or hook. An example
shell script to handle http-01 challenges is provided.
* **tls-alpn-01 challenge support** - The distrubution also includes
**ualpn**, a lightweight proxying tls-alpn-01 challenge responder compliant
with [RFC8737](https://tools.ietf.org/html/rfc8737) and
[RFC8738](https://tools.ietf.org/html/rfc8738).
* **Can run as a cron job** - to renew certificates automatically 
when needed, even for remote machines
* **Robust** - It checks every operation, retrying or failing gracefully
as appropriate
* **Detailed error reporting** - By default totally quiet when everything
works ok, it reports precise and detailed error information on stderr 
when something goes wrong. Optionally it can also print debug information
by specifying the **--verbose** flag once or more.

## Installation
**Note: pristine releases are in the upstream/latest branch, tagged as
upstream/x.x.x**
```
mkdir uacme
wget -O - https://github.com/ndilieto/uacme/archive/upstream/latest.tar.gz | tar zx -C uacme --strip-components=1
cd uacme
./configure --disable-maintainer-mode
make install
```
If you just want to check out the latest pristine release from github:
```
git clone -b upstream/latest https://github.com/ndilieto/uacme
```
Pre-built packages are available for several distributions:

* https://packages.debian.org/bullseye/uacme
* https://packages.ubuntu.com/eoan/uacme
* https://software.opensuse.org/package/uacme
* https://pkgs.alpinelinux.org/packages?name=uacme
* https://github.com/openwrt/packages/tree/master/net/uacme

## Getting started

Once you have obtained **uacme** (see Installation above) the next step is creating
an ACME account:
```
uacme -v -c /path/to/uacme.d new
```
The configuration directory and account private key should have been created:
```
/path/to/uacme.d/private/key.pem
```
You can then issue a certificate for your domain by doing 
```
uacme -v -c /path/to/uacme.d issue www.your.domain.com
```
If everything goes well **uacme** asks you to set up a challenge, for example
```
uacme: challenge=http-01 ident=www.your.domain.com token=kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4
key_auth=kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4.2evcXalKLhAybRuxxE-HkSUihdzQ7ZDAKA9EZYrTXwU
```
Note the challenge type in the example is http-01 which means you should set
up your web server to serve a URL based on the token:
```
http://www.your.domain.com/.well-known/acme-challenge/kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4
```
The URL must return a text file containing a single line with the key
authorization:
```
kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4.2evcXalKLhAybRuxxE-HkSUihdzQ7ZDAKA9EZYrTXwU
```
After setting up the web server you can then type 'y' followed by a newline on
**uacme**'s input. This notifies the ACME server that it can proceed with the
challenge verification.  If the procedure is successful **uacme** saves the
certificate and the key at:
```
/path/to/uacme.d/www.your.domain.com/cert.pem
/path/to/uacme.d/private/www.your.domain.com/key.pem
```
Note other types of challenges are possible. If you type anything other than
'y', **uacme** skips the challenge and proposes a different one. The easiest
is http-01 but any other type can be dealt with. Keep in mind that challenge
types may be served in random order by the server. Do not make any assumptions
and read **uacme**'s output carefully.

## Automating updates
Use the -h flag:
```
uacme -v -c /path/to/uacme.d -h /usr/share/uacme/uacme.sh issue www.your.domain.com
```
or (depending on your installation)
```
uacme -v -c /path/to/uacme.d -h /usr/local/share/uacme/uacme.sh issue www.your.domain.com
```
This will use the example uacme.sh script included in the distribution to 
set up http-01 challenges. You might need to edit the script to match your
webserver's environment.

Once everything works correctly you can also set up cron, for example
```
6 15 * * * /usr/bin/uacme -c /path/to/uacme.d -h /usr/share/uacme/uacme.sh issue www.your.domain.com 
```
The cron job will automatically update the certificate when needed.  Note the
absence of -v flag, this makes **uacme** only produce output upon errors.

Note also that you will need to restart or reload any service that uses the
certificate, to make sure it uses the renewed one. This is system and
installation dependent. I normally put the necessary instructions in another
script (for example /usr/share/uacme/reload.sh) that is executed when **uacme**
returns 0 (indicating the certificate has been reissued).
```
6 15 * * * /usr/bin/uacme -c /path/to/uacme.d -h /usr/share/uacme/uacme.sh issue www.your.domain.com && /usr/share/uacme/reload.sh
```

Check https://github.com/jirutka/muacme for a complete, ready-to-go solution
and https://gitlab.alpinelinux.org/alpine/infra/docker/uacme-nsd-wildcard
for an advanced example with dns-01 challenge management.

## tls-alpn-01 challenge support

**ualpn** is a lightweight proxying tls-alpn-01 challenge responder, designed
to handle incoming HTTPS connections on port 443. Most of the time it just
transparently proxies connections to the real web server (which can be on
either another machine, or a different TCP port on the same machine). When a
tls-alpn-01 challenge handshake comes in, **ualpn** handles it on the fly
instead of proxying it to the webserver.

The event-driven implementation is based on [libev](http://libev.schmorp.de)
and considerably reduces the cost of context switches and memory usage. In
addition on systems such as linux supporting the splice() system call,
**ualpn** is able to move network data without copying it to/from kernel/user
address space.

**ualpn** also listens to a UNIX domain socket so that it can be fed the
necessary tls-alpn-01 key authorizations for the domains being validated
by the ACME server. **ualpn** was designed to be easy to integrate with
not only **uacme** (check the example ualpn.sh hook script) but also other
ACME clients.

To get started with **ualpn**:
* move your real HTTPS server to port 4443 and also enable it to accept
the PROXY protocol:
  * for nginx: https://docs.nginx.com/nginx/admin-guide/load-balancer/using-proxy-protocol
  * for apache: https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html#remoteipproxyprotocol
* launch **ualpn** as a daemon and check the logs (by default in syslog)
```
sudo ualpn -v -d -u nobody:nogroup -c 127.0.0.1@4443 -S 666
```
* create an ACME account
```
uacme -v -s -c /path/to/uacme.d -y new
```
* try obtaining a certificate with tls-alpn-01 challenge
```
uacme -v -s -c /path/to/uacme.d -h /usr/share/uacme/ualpn.sh issue www.your.domain.com
```
or, depending on your installation
```
uacme -v -s -c /path/to/uacme.d -h /usr/local/share/uacme/ualpn.sh issue www.your.domain.com
```

## Documentation

There are regular unix man pages in the distribution, also available in HTML:
[uacme](https://ndilieto.github.io/uacme/uacme.html)
[ualpn](https://ndilieto.github.io/uacme/ualpn.html)

## Bugs and suggestions
If you believe you have found a bug, please log it at https://github.com/ndilieto/uacme/issues

If you have any suggestions for improvements, pull requests are welcome.
