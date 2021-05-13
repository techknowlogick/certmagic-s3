# Certmagic Storage Backend for S3

This library allows you to use any S3-compatible provider as key/certificate storage backend for your [Certmagic](https://github.com/caddyserver/certmagic)-enabled HTTPS server. To protect your keys from unwanted attention, client-side encryption using [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox?tab=doc) is possible.

## What is a S3-compatible service?

In the current state, any service must support the following:

- v4 Signatures
- HTTPS
- A few basic operations:
	- Bucket Exists
	- Get Object
	- Put Object
	- Remove Object
	- Stat Object
	- List Objects

Known good providers/software:

- Minio (with HTTPS enabled)
- Backblaze
- OVH

## Credit

This project was forked from [@thomersch](https://github.com/thomersch)'s wonderful [Certmagic Storage Backend for Generic S3 Providers](https://github.com/thomersch/certmagic-generic-s3) repository.

## License

[Unknown upstream license](https://github.com/thomersch/certmagic-generic-s3/issues/1), please act accordingly.