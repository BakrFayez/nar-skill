// file-io-observe.js
//
// Observe file open, read, write, and delete activity in a running
// Android app. Observation only: the script logs file operations and
// returns them unchanged. It never modifies paths, data, or behavior.
//
// Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
// Licensed under the MIT License. See LICENSE in the repository root.
//
// Usage:
//   frida -U -f <package> -l scripts/frida/file-io-observe.js
//
// Safety: only paths, operation names, and byte counts are logged.
// File contents are never read or printed.

"use strict";

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

// Only log paths containing one of these substrings. Leave the list empty
// to log every path (noisy: the app and the framework open many files).
// Example entries: ["/data/data/com.example/", "Download", ".db"]
var PATH_FILTER = [];

// Log read and write calls in addition to opens. Reads and writes are
// much more frequent than opens; keep this false for a first pass.
var LOG_READ_WRITE = false;

// Log at most this many events in total, then stop logging.
// Set to 0 for no limit.
var MAX_EVENTS = 1000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var eventCount = 0;

function pathAllowed(path) {
    if (PATH_FILTER.length === 0) {
        return true;
    }
    for (var i = 0; i < PATH_FILTER.length; i++) {
        if (path.indexOf(PATH_FILTER[i]) !== -1) {
            return true;
        }
    }
    return false;
}

function logEvent(text, path) {
    if (MAX_EVENTS > 0 && eventCount >= MAX_EVENTS) {
        return;
    }
    if (path !== null && !pathAllowed(path)) {
        return;
    }
    eventCount++;
    console.log("[file-io] " + text);
}

function pathOf(fileOrString) {
    try {
        if (typeof fileOrString === "string") {
            return fileOrString;
        }
        return fileOrString.getAbsolutePath();
    } catch (e) {
        return "<unknown path>";
    }
}

function hookConstructor(className, label) {
    var clazz;
    try {
        clazz = Java.use(className);
    } catch (e) {
        console.log("[file-io] class not found, skipped: " + className);
        return;
    }
    try {
        clazz.$init.overloads.forEach(function (overload) {
            overload.implementation = function () {
                var path = pathOf(arguments[0]);
                var mode = "";
                if (arguments.length > 1 && typeof arguments[1] === "boolean") {
                    mode = arguments[1] ? " append" : "";
                }
                if (arguments.length > 1 && typeof arguments[1] === "string") {
                    mode = " mode=" + arguments[1];
                }
                logEvent("open " + label + " " + path + mode, path);
                return overload.apply(this, arguments);
            };
        });
        console.log("[file-io] hooked: " + className + " constructor");
    } catch (e) {
        console.log("[file-io] could not hook " + className + ": " + e);
    }
}

function hookFileOps() {
    var File;
    try {
        File = Java.use("java.io.File");
    } catch (e) {
        console.log("[file-io] java.io.File not found, skipped.");
        return;
    }
    var ops = ["delete", "mkdir", "mkdirs", "renameTo"];
    ops.forEach(function (name) {
        try {
            File[name].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var path = pathOf(this);
                    var extra = "";
                    if (name === "renameTo") {
                        extra = " -> " + pathOf(arguments[0]);
                    }
                    logEvent(name + " " + path + extra, path);
                    return overload.apply(this, arguments);
                };
            });
            console.log("[file-io] hooked: java.io.File." + name);
        } catch (e) {
            console.log("[file-io] could not hook File." + name + ": " + e);
        }
    });
}

// libcore.io.IoBridge.open is the low-level open behind FileInputStream,
// FileOutputStream, RandomAccessFile, and other Java file APIs. Hooking
// it catches opens that bypass the java.io constructors.
function hookIoBridge() {
    var IoBridge;
    try {
        IoBridge = Java.use("libcore.io.IoBridge");
    } catch (e) {
        console.log("[file-io] libcore.io.IoBridge not found, skipped.");
        return;
    }
    try {
        IoBridge.open.overloads.forEach(function (overload) {
            overload.implementation = function (path, flags) {
                var flagText = "";
                try {
                    // O_ACCMODE bits: 0 = read, 1 = write, 2 = read/write.
                    var mode = flags & 3;
                    flagText = mode === 0 ? " read"
                        : mode === 1 ? " write" : " read/write";
                } catch (e) {
                    // Flags are best effort.
                }
                logEvent("open (IoBridge) " + path + flagText, path);
                return overload.apply(this, arguments);
            };
        });
        console.log("[file-io] hooked: libcore.io.IoBridge.open");
    } catch (e) {
        console.log("[file-io] could not hook IoBridge.open: " + e);
    }
}

// Byte-count-only read/write observation. Contents are never logged.
function hookReadWrite() {
    if (!LOG_READ_WRITE) {
        return;
    }
    var classes = [
        { name: "java.io.FileInputStream", method: "read" },
        { name: "java.io.FileOutputStream", method: "write" },
        { name: "java.io.RandomAccessFile", method: "read" },
        { name: "java.io.RandomAccessFile", method: "write" },
    ];
    classes.forEach(function (entry) {
        var clazz;
        try {
            clazz = Java.use(entry.name);
        } catch (e) {
            return;
        }
        try {
            clazz[entry.method].overloads.forEach(function (overload) {
                overload.implementation = function () {
                    var result = overload.apply(this, arguments);
                    var n = "";
                    if (typeof result === "number") {
                        n = " bytes=" + result;
                    } else if (arguments.length > 0 && arguments[0]
                        && typeof arguments[0].length === "number") {
                        n = " bytes=" + arguments[0].length;
                    }
                    logEvent(entry.method + " " + entry.name + n, null);
                    return result;
                };
            });
        } catch (e) {
            console.log("[file-io] could not hook " + entry.name + "."
                + entry.method + ": " + e);
        }
    });
    console.log("[file-io] read/write observation enabled (byte counts only).");
}

if (typeof Java === "undefined" || !Java.available) {
    console.log("[file-io] Java runtime is not available in this process.");
} else {
    Java.perform(function () {
        console.log("[file-io] observing file operations. "
            + "Paths and byte counts only; contents are never logged.");
        hookConstructor("java.io.FileInputStream", "FileInputStream");
        hookConstructor("java.io.FileOutputStream", "FileOutputStream");
        hookConstructor("java.io.RandomAccessFile", "RandomAccessFile");
        hookFileOps();
        hookIoBridge();
        hookReadWrite();
    });
}
