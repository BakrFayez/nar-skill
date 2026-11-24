// jni-trace.js
//
// Trace JNI native-method registration and native call entry.
// Observation only: the script logs what the app registers and calls.
// It never modifies native code, arguments, or return values.
//
// Part of NAR (Nirous Android Reversing). Research by Bakr Fayez.
// Licensed under the MIT License. See LICENSE in the repository root.
//
// Usage:
//   frida -U -f <package> -l scripts/frida/jni-trace.js
//
// How it works: RegisterNatives is entry 215 (0-based) of the JNI
// function table, so the script reads its address from the table
// instead of relying on a libart.so export. When the app registers
// native methods, each JNINativeMethod entry (name, signature,
// function pointer) is logged, and the native function is watched
// for entry. A libart.so export lookup is kept as a fallback.
//
// Safety: only method names, signatures, and addresses are logged.
// No argument or memory contents are printed.

"use strict";

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------

// Watch each registered native function for entry calls.
// Set to false to log registrations only.
var TRACE_NATIVE_ENTRY = true;

// Log at most this many native entry calls in total, then stop logging
// entries (registrations keep logging). Set to 0 for no limit.
var MAX_ENTRY_CALLS = 500;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

var entryCount = 0;
var watchedFunctions = {};

function describeAddress(address) {
    try {
        var symbol = DebugSymbol.fromAddress(address);
        var module = symbol.moduleName ? symbol.moduleName : "?";
        var name = symbol.name ? symbol.name : "?";
        var offset = "";
        try {
            var mod = Process.findModuleByAddress(address);
            if (mod !== null) {
                offset = " +0x" + address.sub(mod.base).toString(16);
            }
        } catch (e) {
            // Offset is best effort.
        }
        return module + "!" + name + offset + " (" + address + ")";
    } catch (e) {
        return String(address);
    }
}

function watchNativeFunction(fnPtr, label) {
    var key = fnPtr.toString();
    if (watchedFunctions[key]) {
        return;
    }
    watchedFunctions[key] = true;
    try {
        Interceptor.attach(fnPtr, {
            onEnter: function (args) {
                if (!TRACE_NATIVE_ENTRY) {
                    return;
                }
                if (MAX_ENTRY_CALLS > 0 && entryCount >= MAX_ENTRY_CALLS) {
                    return;
                }
                entryCount++;
                console.log("[jni-entry] " + label + " thread=" + this.threadId
                    + " at " + describeAddress(fnPtr));
            }
        });
    } catch (e) {
        console.log("[jni-trace] could not watch " + label + ": " + e);
    }
}

// Read one JNINativeMethod struct: { const char* name; const char* sig;
// void* fnPtr; }. Each field is one pointer wide.
function readNativeMethod(methodsPtr, index) {
    var entry = methodsPtr.add(index * Process.pointerSize * 3);
    // NativePointer instance methods: the Memory.readPointer /
    // Memory.readUtf8String statics were removed in Frida 17
    // (the class-line event fired but the per-method read threw
    // until this was fixed — found live, Evolution Phase 6).
    var namePtr = entry.readPointer();
    var sigPtr = entry.add(Process.pointerSize).readPointer();
    var fnPtr = entry.add(Process.pointerSize * 2).readPointer();
    var name = "";
    var sig = "";
    try { name = namePtr.readUtf8String(); } catch (e) { name = "?"; }
    try { sig = sigPtr.readUtf8String(); } catch (e) { sig = "?"; }
    return { name: name, sig: sig, fnPtr: fnPtr };
}

function classNameFromJClass(jclass) {
    try {
        var Class = Java.use("java.lang.Class");
        var cls = Java.cast(jclass, Class);
        return cls.getName();
    } catch (e) {
        return "<unknown class " + jclass + ">";
    }
}

function hookRegisterNatives(address, source) {
    if (address === null || address.isNull()) {
        return false;
    }
    try {
        Interceptor.attach(address, {
            onEnter: function (args) {
                // args[0] = JNIEnv*, args[1] = jclass,
                // args[2] = JNINativeMethod*, args[3] = method count.
                var jclass = args[1];
                var methodsPtr = args[2];
                var count = args[3].toInt32();
                var clsName = classNameFromJClass(jclass);
                console.log("[jni-register] class=" + clsName
                    + " methods=" + count + " via " + source);
                for (var i = 0; i < count; i++) {
                    var m = readNativeMethod(methodsPtr, i);
                    console.log("[jni-register]   " + m.name + " " + m.sig
                        + " -> " + describeAddress(m.fnPtr));
                    if (TRACE_NATIVE_ENTRY) {
                        watchNativeFunction(m.fnPtr, clsName + "." + m.name);
                    }
                }
            }
        });
        console.log("[jni-trace] hooked RegisterNatives at " + address
            + " (" + source + ")");
        return true;
    } catch (e) {
        console.log("[jni-trace] failed to hook RegisterNatives at "
            + address + ": " + e);
        return false;
    }
}

function findRegisterNativesInLibart() {
    var matches = [];
    try {
        Module.enumerateExports("libart.so").forEach(function (exp) {
            if (exp.name.indexOf("RegisterNatives") !== -1) {
                matches.push(exp);
            }
        });
    } catch (e) {
        // libart.so may not be loaded yet when the script runs.
    }
    return matches;
}

if (typeof Java === "undefined" || !Java.available) {
    console.log("[jni-trace] Java runtime is not available in this process.");
} else {
    Java.perform(function () {
        // Primary path: read RegisterNatives from the JNI function table.
        // The table pointer is the first field of the JNIEnv struct, and
        // RegisterNatives is entry 215 (0-based) in that table.
        var hooked = false;
        try {
            var env = Java.vm.getEnv();
            var functionTable = env.handle.readPointer();
            var registerNatives = functionTable
                .add(215 * Process.pointerSize).readPointer();
            hooked = hookRegisterNatives(registerNatives, "JNIEnv table");
        } catch (e) {
            console.log("[jni-trace] JNIEnv table lookup failed: " + e);
        }
        if (!hooked) {
            // Fallback: look for a RegisterNatives export in libart.so.
            var matches = findRegisterNativesInLibart();
            if (matches.length === 0) {
                console.log("[jni-trace] RegisterNatives not found. "
                    + "The app may register natives before this script loads; "
                    + "spawn the app with -f so the script loads first.");
            }
            matches.forEach(function (exp) {
                hookRegisterNatives(exp.address, "libart export " + exp.name);
            });
        }
    });
}
