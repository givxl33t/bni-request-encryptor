# BNI Request Encryptor API

A small REST wrapper around the BNI request-body encryption functions. The API accepts a `client_id` and `secret_key` with each request; send traffic over TLS and avoid logging request bodies because they contain credentials.

## API

- `POST /api/v1/encrypt` encrypts a JSON payload and returns its Base64URL-encoded value.
- `POST /api/v1/decrypt` decrypts a value and returns the payload as a JSON string. BNI encrypted values expire after 8 minutes.
- `GET /healthz` returns `{"status":"ok"}`.
- `GET /swagger` opens the interactive Swagger UI.
- `GET /swagger.yaml` serves the OpenAPI specification.

Example encrypt request:

```json
{
	"client_id": "000",
	"secret_key": "0123456789abcdef0123456789abcdef",
	"payload": {
		"type": "createbilling",
		"client_id": "000",
		"trx_id": "INV-0001",
		"trx_amount": "1000",
		"billing_type": "c",
		"customer_name": "Test Customer"
	}
}
```

The encrypt response is `{"encrypted":"..."}`. Decrypt requests use `client_id`, `secret_key`, and `encrypted`, and return `{"payload":"..."}`.

The encryption endpoint accepts `createbilling`, `createbillingsms`, `updatebilling`, and `inquirybilling` payloads. The payload's `client_id` must match the top-level ID. BNI's 32-character hexadecimal secret key is required. Amounts must be integer strings of up to 14 digits; billing types are `o`, `c`, `i`, `m`, `n`, or `x`. Open-payment creation (`billing_type: "o"`) requires an amount of `"0"`; SMS billing (`type: "createbillingsms"`) requires fixed payment (`billing_type: "c"`). Operation-specific required fields and optional field formats are defined in [`swagger.yaml`](swagger.yaml).

## Run with Docker

Build and start the container (the service is not intended to be run directly on the host):

```sh
docker build -t bni-request-encryptor .
docker run --rm -p 8080:8080 bni-request-encryptor
```

Set `PORT` to change the listen port inside the container. The default is `8080`.

The cipher and timestamp validation are retained from the supplied implementation. This wrapper does not replace TLS, access control, or secret management; provide those at the deployment boundary.