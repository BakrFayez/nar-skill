// java-api-trace.js
//
// Trace calls of named Java methods in a running Android app.
// Observation only: the script logs calls and returns them unchanged.
// It never modifies arguments, return values, or app behavior.
//
// Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
// Licensed under the MIT License. See LICENSE in the repository root.
//
// Usage:
//   frida -U -f <package> -l scripts/frida/java-api-trace.js
//
// Safety: string arguments are logged by length only, never by value,
// so passwords, tokens, and session data never appear in the output.

"use strict";

// ---------------------------------------------------------------------------
// CONFIG: edit this list to trace the methods your analysis needs.
// Each entry names one class and one method. All overloads are traced.
// Use fully qualified class names, for example "com.example.ApiClient".
// ---------------------------------------------------------------------------
var TARGETS = [
    // { className: "com.example.ApiClient", methodName: "login" },
    // { className: "com.example.Store", methodName: "purchase" },
    { className: "java.net.URL", methodName: "openConnection" },
];

// Log at most this many calls per method, then stop logging that method.
// This keeps a hot method from flooding the log. Set to 0 for no limit.
var MAX_CALLS_PER_METHOD = 200;

// Log return values (type and, for strings, length only). Set to false
// to log calls only.
var LOG_RETURNS = true;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Describe one value without ever printing string contents.
function describe(value) {
    if (value === null || value === undefined) {
        return "null";
    }
    var t = typeof value;
    if (t === "number" || t === "boolean") {
        return String(value);
    }
    if (t === "string") {
        return "<string len=" + value.length + ">";
    }
    if (t === "object") {
        try {
            var cls = value.getClass();
            if (cls !== null) {
                return "<" + cls.getName() + ">";
            }
        } catch (e) {
            // Fall through to the generic form.
        }
        return "<object>";
    }
    return "<" + t + ">";
}

function describeArgs(args) {
    var parts = [];
    for (var i = 0; i < args.length; i++) {
        parts.push(describe(args[i]));
    }
    return parts.join(", ");
}

function hookMethod(className, methodName) {
    var clazz;
    try {
        clazz = Java.use(className);
    } catch (e) {
        console.log("[java-api-trace] class not found, skipped: " + className);
        return;
    }
    var method;
    try {
        method = clazz[methodName];
    } catch (e) {
        method = null;
    }
    if (!method || !method.overloads) {
        console.log("[java-api-trace] method not found, skipped: "
            + className + "." + methodName);
        return;
    }
    var count = 0;
    method.overloads.forEach(function (overload) {
        var sig = className + "." + methodName + "("
            + overload.argumentTypes.map(function (a) {
                return a.className;
            }).join(", ") + ")";
        overload.implementation = function () {
            if (MAX_CALLS_PER_METHOD > 0 && count >= MAX_CALLS_PER_METHOD) {
                return overload.apply(this, arguments);
            }
            count++;
            console.log("[call] " + sig + " args=[" + describeArgs(arguments) + "]");
            var result = overload.apply(this, arguments);
            if (LOG_RETURNS) {
                console.log("[return] " + sig + " -> " + describe(result));
            }
            return result;
        };
        console.log("[java-api-trace] hooked: " + sig);
    });
}

if (typeof Java === "undefined" || !Java.available) {
    console.log("[java-api-trace] Java runtime is not available in this process.");
} else {
    Java.perform(function () {
        console.log("[java-api-trace] tracing " + TARGETS.length
            + " target method(s). String values are never printed.");
        TARGETS.forEach(function (t) {
            hookMethod(t.className, t.methodName);
        });
    });
}
