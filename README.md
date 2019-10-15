# Makk.es Auth Service

This is the code of the Auth Service running at https://auth.services.makk.es. A
documentation of the REST API provided by Auth Service is available at
https://rel.services.makk.es and the JSON Home Document can be found at
https://services.makk.es/json-home.json.

## Configuration/Persistence

The startup configuration is provided via environment variables:

|Variable|Description|Default
|---|---|---
|`LOG_LEVEL`|The log level on the server. One of `DEBUG`, `INFO`, `WARN`, `ERROR`|`INFO`
|`LISTEN_HOST`|The IP address/hostname to listen on|`localhost`
|`LISTEN_PORT`|The port to listen on|`4242`
|`SERVE_PORT`|The port used by users to reach the service|empty
|`SERVE_HOST`|The host used by users to reach the service|`localhost`
|`SERVE_PROTOCOL`|One of `http` or `https`|`https`
|`DB_TYPE`|The persistence backend to use, one of `postgres`, `dynamodb`, `inmemory`|`postgres`

### DynamoDB Backend Configuration

The DynamoDB backend is configured via standard AWS environment variables; see
https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html?shortFooter=true
for an explanation.

The table to be used is configured via the environment variable
`DYNAMODB_TABLE`, the default for that value is `auth`.
