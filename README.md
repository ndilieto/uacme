<img src="https://repository-images.githubusercontent.com/182530051/6d85b680-8e9d-11e9-91b9-0bc9eefac05e" alt="uacme manual">

# uacme
lightweight client for the [RFC8555](https://tools.ietf.org/html/rfc8555) 
ACMEv2 protocol, written in plain C code with minimal dependencies
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
* **Minimal dependencies** - Other than the standard C library, uacme 
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
(including http-01, dns-01 and others) but leaves the task of setting up 
and cleaning up the challenge environment to the user or hook. An example
shell script to handle http-01 challenges is provided.
* **Can run as a cron job** - to renew certificates automatically 
when needed, even for remote machines
* **Robust** - It checks every operation, retrying or failing gracefully
as appropriate
* **Detailed error reporting** - By default totally quiet when everything
works ok, it reports precise and detailed error information on stderr 
when something goes wrong. Optionally it can also print debug information
by specifying the **--verbose** flag once or more.

## Installation
```
mkdir uacme
wget -O - https://github.com/ndilieto/uacme/archive/upstream/latest.tar.gz | tar zx -C uacme --strip-components=1
cd uacme
./configure --disable-maintainer-mode
make install
```
You'll also find the latest release in the git repository:
```
git clone -b upstream/latest https://github.com/ndilieto/uacme
```

## Getting started

Once you have obtained uacme (see Installation above), the next step is to use
```
uacme -v -c /path/to/uacme.d new
```
to create an ACME account. This will create the configuration folder and account
private key:
```
/path/to/uacme.d/private/key.pem
```
You can then issue a certificate for your domain by doing 
```
uacme -v -c /path/to/uacme.d issue www.your.domain.com
```
If everything goes well, uacme will ask you to set up a challenge, for example
```
uacme: challenge=http-01 ident=www.your.domain.com token=kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4
key_auth=kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4.2evcXalKLhAybRuxxE-HkSUihdzQ7ZDAKA9EZYrTXwU
```
Note the challenge type in the example is http-01 which means you should set up your web server
to serve a URL based on the token:
```
http://www.your.domain.com/.well-known/acme-challenge/kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4
```
The URL must return a text file containing a single line with the key authorization:
```
kZjqYgAss_sl4XXDfFq-jeQV1_lqsE76v2BoCGegFk4.2evcXalKLhAybRuxxE-HkSUihdzQ7ZDAKA9EZYrTXwU
```
once you set up the above, you can then type 'y' followed by a newline on uacme's
input and it will proceed with the challenge. If everything goes well, the following
will be created:
```
/path/to/uacme.d/www.your.domain.com/cert.pem
/path/to/uacme.d/private/www.your.domain.com/key.pem
```
Note other types of challenges are possible. If you type anything other than 'y',
uacme will skip the challenge and propose a different one. The easiest is http-01 but
any other type can be dealt with. Keep in mind that challenge types may be served in
random order by the server. Do not make any assumptions and read uacme's output carefully.

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
The cron job will automatically update the certificate when needed. 
Note the absence of -v flag, this makes uacme only produce output upon errors.

Note also that you will need to restart or reload any service that 
uses the certificate, to make sure it uses the renewed one.
This is system and installation dependent. I normally put the necessary
instructions in another script (for example /usr/share/uacme/reload.sh)
that is executed when uacme returns 0 (indicating the certificate has
been reissued).
```
6 15 * * * /usr/bin/uacme -c /path/to/uacme.d -h /usr/share/uacme/uacme.sh issue www.your.domain.com && /usr/share/uacme/reload.sh
```
## Documentation

There is a regular unix man page in the distribution, also available
[here](https://ndilieto.github.io/uacme)

## Bugs and suggestions
If you believe you have found a bug, please log it at https://github.com/ndilieto/uacme/issues

If you have any suggestions for improvements, pull requests are welcome.
