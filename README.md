# Certmagic Storage Backend for S3

This library allows you to use any S3-compatible provider as key/certificate storage backend for your [Certmagic](https://github.com/caddyserver/certmagic)-enabled HTTPS server. To protect your keys from unwanted attention, client-side encryption using [secretbox](https://pkg.go.dev/golang.org/x/crypto/nacl/secretbox?tab=doc) is possible.

## Configuration Options

- `endpoint`: Custom endpoint URL (optional, defaults to "https://s3.amazonaws.com")
- `host`: **Deprecated** - Use `endpoint` instead.
- `insecure`: Skip TLS certificate verification (optional, defaults to `false`)
- `bucket`: S3 bucket name (required, no default value)
- `region`: AWS region (optional,defaults to `us-east-1`)
- `access_key`: AWS access key (optional)
- `secret_key`: AWS secret key (optional)
- `profile`: AWS profile name (optional)
- `role_arn`: IAM role ARN for role assumption (optional)
- `prefix`: Object key prefix (defaults to "acme")
- `encryption_key`: 32-byte encryption key for client-side encryption (optional, if not set then files will be plaintext in object storage)
- `use_path_style`: Force path-style URLs (optional, enforced as `true` when custom endpoint used)

If both `host` and `endpoint` are specified, `endpoint` takes precedence.

## What is an S3-compatible service?

Any service must support the following:

- v4 Signatures
- Basic S3 operations:
	- GetObject
	- PutObject
	- DeleteObject
	- HeadObject
	- ListObjectsV2

## Configuration Examples

### Using Static Credentials (AWS S3)
```caddyfile
{
  storage s3 {
    bucket "my-certificates"
    region "us-west-2"
    access_key "AKIAEXAMPLE"
    secret_key "EXAMPLE"
    prefix "caddy-certs"
    encryption_key "your-32-byte-encryption-key-here"
  }
}
```

### Using Custom S3-Compatible Provider
```caddyfile
{
  storage s3 {
    endpoint "https://minio.example.com"
    bucket "my-certificates"
    region "us-east-1"
    access_key "minioadmin"
    secret_key "minioadmin"
    prefix "caddy-certs"
  }
}
```

## Credits & Thanks

This project was forked from [@thomersch](https://github.com/thomersch)'s wonderful [Certmagic Storage Backend for Generic S3 Providers](https://github.com/thomersch/certmagic-generic-s3) repository.

## License

This project is licensed under [Apache 2.0](https://github.com/thomersch/certmagic-generic-s3/issues/1), an open source license.
