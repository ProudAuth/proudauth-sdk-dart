/// `dart:io` adapter for the request helpers: [protect] wraps an
/// `HttpServer` handler so it runs only with verified claims, and
/// [protectOperation] does the same for routes that also serve support
/// sessions. Not available on the web.
library;

export 'src/io_adapter.dart'
    show
        HttpRequestHandler,
        authenticateHttpRequest,
        claimsOf,
        protect,
        protectOperation,
        sendChallenge;
