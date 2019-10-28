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
