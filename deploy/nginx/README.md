# TLS certificates for the bundled proxy

`docker-compose.yml` mounts this directory into the nginx container at
`/etc/nginx/certs`, read only. Two files are expected:

| File            | Contents                                     |
| --------------- | -------------------------------------------- |
| `fullchain.pem` | Server certificate followed by any intermediates |
| `privkey.pem`   | Matching private key, unencrypted (nginx cannot prompt for a passphrase) |

## Option 1: a certificate from your own CA or provider

Copy the two files in with the names above. Keep `privkey.pem` at mode `600` and
never commit it. The `.gitignore` at the repository root already excludes
`*.key` and this `certs/` directory's contents are ignored by the `secrets/` and
`*.key` rules; verify with `git status` before your first commit.

## Option 2: a self signed certificate for a lab or pilot

Fine for an internal trial, not for anything an auditor will look at. Browsers
will warn, and you will have to accept the exception once.

```sh
mkdir -p deploy/nginx/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout deploy/nginx/certs/privkey.pem \
  -out deploy/nginx/certs/fullchain.pem \
  -subj "/CN=cxcreditguard.internal" \
  -addext "subjectAltName=DNS:cxcreditguard.internal,DNS:localhost,IP:127.0.0.1"
chmod 600 deploy/nginx/certs/privkey.pem
```

Note that HSTS is enabled by default (`CXCG_HSTS_ENABLED=true`). Once a browser
has seen the HSTS header on a hostname, it will refuse plain HTTP to that
hostname for a year. Use a dedicated hostname for testing, or set
`CXCG_HSTS_ENABLED=false` until you have a real certificate.

## Option 3: your existing ingress

If you already terminate TLS at a load balancer or ingress controller, drop the
`proxy` service from `docker-compose.yml` and point your ingress at the `app`
service on port 8000. Two requirements:

- Forward `X-Forwarded-Proto: https`, so the app knows the connection is secure.
- Keep `CXCG_COOKIE_SECURE=true`. Session cookies are marked `Secure`, and a
  browser will silently discard them over plain HTTP, which looks like "login
  does nothing" rather than like an error.
