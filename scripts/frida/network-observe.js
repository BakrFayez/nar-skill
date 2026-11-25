// network-observe.js
//
// Observe network connections an Android app opens: HttpURLConnection,
// OkHttp, and plain sockets. Observation only: the script logs
// connection attempts and returns them unchanged. It never modifies
// requests, responses, or TLS behavior, and it performs no interception
// or bypass of any kind.
//
// Part of NAR (Nirous Android Reversing).
// Licensed under the MIT License. See LICENSE in the repository root.
//
// Usage:
//   frida -U -f <package> -l scripts/frida/network-observe.js
//
// Safety: URLs are logged without query values, header names are logged
// without header values, and bodies are never read or printed. Tokens,
// session cookies, and credentials therefore never appear in the output.

"use strict";

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

// Highlight connections whose host contains one of these substrings
// with a [watch] marker. Leave empty to disable highlighting.
var WATCH_HOSTS = [];

// Log at most this many connection events in total, then stop logging.
// Set to 0 for no limit.
var MAX_EVENTS = 500;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var eventCount = 0;

// Strip query values and fragments from a URL string. Keeps scheme,
// host, port, and path, and notes only the length of the query.
function redactUrl(raw) {
    try {
        var url = String(raw);
        var hash = url.indexOf("#");
        if (hash !== -1) {
            url = url.substring(0, hash);
        }
        // Strip URL userinfo (user:password@): the query
        // is length-masked below, but the authority's
        // credentials previously survived into the log,
        // contradicting this script's own header (D-12).
        url = url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/i,
                          "$1REDACTED@");
        var query = url.indexOf("?");
        if (query === -1) {
            return url;
        }
        var queryLen = url.length - query - 1;
        return url.substring(0, query) + "?<query len=" + queryLen + ">";
    } catch (e) {
        return "<unreadable url>";
    }
}

function isWatched(host) {
    if (!host) {
        return false;
    }
    for (var i = 0; i < WATCH_HOSTS.length; i++) {
        if (host.indexOf(WATCH_HOSTS[i]) !== -1) {
            return true;
        }
    }
    return false;
}

function logEvent(text, host) {
    if (MAX_EVENTS > 0 && eventCount >= MAX_EVENTS) {
        return;
    }
    eventCount++;
    var marker = isWatched(host) ? "[watch] " : "";
    console.log("[net] " + marker + text);
}

function hookUrlConnection() {
    var URL;
    try {
        URL = Java.use("java.net.URL");
    } catch (e) {
        console.log("[net] java.net.URL not found, skipped.");
        return;
    }
    try {
        URL.openConnection.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var conn = overload.apply(this, arguments);
                var raw = "";
                try { raw = this.toString(); } catch (e) { raw = "?"; }
                var host = "";
                try { host = this.getHost(); } catch (e) { host = ""; }
                logEvent("openConnection " + redactUrl(raw), host);
                return conn;
            };
        });
        console.log("[net] hooked: java.net.URL.openConnection");
    } catch (e) {
        console.log("[net] could not hook URL.openConnection: " + e);
    }

    var HttpURLConnection;
    try {
        HttpURLConnection = Java.use("java.net.HttpURLConnection");
    } catch (e) {
        console.log("[net] java.net.HttpURLConnection not found, skipped.");
        return;
    }
    try {
        HttpURLConnection.connect.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var raw = "";
                var host = "";
                try { raw = this.getURL().toString(); } catch (e) { raw = "?"; }
                try { host = this.getURL().getHost(); } catch (e) { host = ""; }
                var method = "";
                try { method = this.getRequestMethod(); } catch (e) { method = "?"; }
                logEvent("connect " + method + " " + redactUrl(raw), host);
                return overload.apply(this, arguments);
            };
        });
        console.log("[net] hooked: java.net.HttpURLConnection.connect");
    } catch (e) {
        console.log("[net] could not hook HttpURLConnection.connect: " + e);
    }
    try {
        HttpURLConnection.getResponseCode.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var code = overload.apply(this, arguments);
                var raw = "";
                var host = "";
                try { raw = this.getURL().toString(); } catch (e) { raw = "?"; }
                try { host = this.getURL().getHost(); } catch (e) { host = ""; }
                logEvent("response " + code + " " + redactUrl(raw), host);
                return code;
            };
        });
        console.log("[net] hooked: java.net.HttpURLConnection.getResponseCode");
    } catch (e) {
        console.log("[net] could not hook HttpURLConnection.getResponseCode: " + e);
    }
}

// OkHttp: hook newCall to log the request URL and method, plus header
// names (never values). OkHttp may be absent or shaded under another
// package; a missing class is logged and skipped, not an error.
function hookOkHttp() {
    var OkHttpClient;
    try {
        OkHttpClient = Java.use("okhttp3.OkHttpClient");
    } catch (e) {
        console.log("[net] okhttp3.OkHttpClient not found, skipped. "
            + "If the app uses OkHttp under a shaded package, adapt the "
            + "class name in this script.");
        return;
    }
    try {
        OkHttpClient.newCall.overloads.forEach(function (overload) {
            overload.implementation = function (request) {
                var call = overload.apply(this, arguments);
                try {
                    var url = request.url().toString();
                    var method = request.method();
                    var host = request.url().host();
                    var headerNames = [];
                    try {
                        var headers = request.headers();
                        var names = headers.names();
                        var it = names.iterator();
                        while (it.hasNext()) {
                            headerNames.push(it.next());
                        }
                    } catch (e2) {
                        // Header names are best effort.
                    }
                    logEvent("okhttp " + method + " " + redactUrl(url)
                        + " headers=[" + headerNames.join(", ") + "]", host);
                } catch (e3) {
                    logEvent("okhttp newCall (request unreadable)", "");
                }
                return call;
            };
        });
        console.log("[net] hooked: okhttp3.OkHttpClient.newCall");
    } catch (e) {
        console.log("[net] could not hook OkHttpClient.newCall: " + e);
    }
}

function hookSocket() {
    var Socket;
    try {
        Socket = Java.use("java.net.Socket");
    } catch (e) {
        console.log("[net] java.net.Socket not found, skipped.");
        return;
    }
    try {
        Socket.connect.overloads.forEach(function (overload) {
            overload.implementation = function (endpoint) {
                var host = "";
                var port = "";
                try {
                    var addr = endpoint.getAddress();
                    host = addr.getHostAddress();
                    port = endpoint.getPort();
                } catch (e) {
                    // Endpoint details are best effort.
                }
                logEvent("socket connect " + host + ":" + port, host);
                return overload.apply(this, arguments);
            };
        });
        console.log("[net] hooked: java.net.Socket.connect");
    } catch (e) {
        console.log("[net] could not hook Socket.connect: " + e);
    }
}

if (typeof Java === "undefined" || !Java.available) {
    console.log("[net] Java runtime is not available in this process.");
} else {
    Java.perform(function () {
        console.log("[net] observing network connections. "
            + "Query values, header values, and bodies are never logged.");
        hookUrlConnection();
        hookOkHttp();
        hookSocket();
    });
}
