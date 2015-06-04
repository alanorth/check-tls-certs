## Golang Check TLS Certificates

This Heroku Golang app is a fork of [Ryan Rogers' go-check-certs](https://github.com/timewasted/go-check-certs) which checks the expiry dates and signature algorithms of an SSL certificate for a given host.
Warning messages are displayed if a certificate expires in less than 30 days and also if the signature algorithm has already been [sunset](http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html).


### Usage

This app runs on heroku as a worker process & sends e-mail notifications via [Mandrill](http://mandrill.com/) to administrators if a certificate of a given host expires within X days or if its signature algorithm has already been sunset.

To receive e-mail notifications, you'll need to specify the following OS environment variables:
- `EMAIL_DEST_ADDR`: A space separated list of e-mail address(es) which notifications will be sent to.
- `EMAIL_SRC_ADDR`: E-mail address which Mandrill will use to send notifications on behalf of.
- `MANDRILL_KEY`: Mandrill API key

This app uses the following options:
- `-hosts`: path to a file containing a list of hosts to check. Each line uses the syntax `hostname:port`, empty lines or lines that start with `#` are ignored.
- `-years`: warn if the certificate expires within X years. Defaults to 0 years.
- `-months`: warn if the certificate expires within X months. Defaults to 0 months.
- `-days`: warn if the certificate expires within X days. Defaults to 30 days.
- `-concurrency`: Maximum number of hosts to check at once. Defaults to 8 hosts.
- `-check-sig-alg`: Check certificate's signature algorithm. Defaults to true.

Examples usage:
```
$ go run main.go -hosts=hosts -days=30
2015/06/04 14:53:27 no certifcate(s) are/is expiring in 0 years, 0 months, 30 days

$ go run main.go -hosts=hosts -years=1 -months=3 -days=2
2015-06-04 11:54:12 UTC: cgspace.cgiar.org:443: 'cgspace.cgiar.org' (S/N 40D4587A33E30) expires in roughly 303 days.
```


### Deploying to heroku
- clone the repo & create a golang app on heroku:

        git clone https://github.com/ilri/rmg-check-tls-certs.git
        heroku apps:create <APP-NAME> --buildpack https://github.com/kr/heroku-buildpack-go.git

- Specify `EMAIL_DEST_ADDR`, `EMAIL_SRC_ADDR` & `MANDRILL_KEY` environment variables under _Config Variables_ in the application's Setting page on heroku dashboard.
- Specify the app's name in the `Procfile`

        worker: <APP-NAME> -hosts=hosts <OTHER-OPTIONS>
- push to deploy

        git push heroku master



### License
```
Copyright (c) 2013, Ryan Rogers
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
