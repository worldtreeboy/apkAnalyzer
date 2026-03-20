/*
 * Universal Bypass v17 — The Pre-Emptive Strike
 *
 * Philosophy: Be faster than the enemy's constructor.
 *
 * v17 Changes (from v16):
 *   - CRITICAL FIX: v16's dlopen onLeave was TOO LATE — by the time dlopen
 *     returns, DT_INIT_ARRAY has already run and crashed at 0x66ff4.
 *   - NEW METHOD A: Hook linker's call_constructors(). This fires AFTER the
 *     module's segments are mmap'd but BEFORE DT_INIT/DT_INIT_ARRAY execute.
 *     We scan for the target module and patch it in the pre-constructor window.
 *   - NEW METHOD B: Hook mmap in linker64 (or libc fallback). Track the fd
 *     returned by openat for libvosWrapperEx.so. When mmap maps the .text
 *     segment containing offset 0x66ff4, patch it instantly — even before
 *     call_constructors fires.
 *   - METHOD C (safety net): dlopen onLeave kept as final fallback.
 *   - NEW: __system_property_read_callback hook (Android 12+ native path)
 *     in addition to __system_property_get.
 *   - KEPT: MemFD Phantom, thread stealth, abort auto-NOP, full lobotomy,
 *     string neutralizer, readlink concealment, stat camouflage.
 *
 * Hook timeline during library load:
 *   1. openat("libvosWrapperEx.so")      → fd tracked
 *   2. mmap(fd, offset, len) returns      → PATCH 0x66ff4 (Method B)
 *   3. call_constructors(soinfo*)         → PATCH if not yet done (Method A)
 *   4. DT_INIT_ARRAY runs                → 0x66ff4 is already RET → no crash
 *   5. android_dlopen_ext returns         → full lobotomy scan (Method C)
 *
 * Architecture: Pure Interceptor + Memory.patchCode. No Stalker. No Java.
 *
 * ARM64 instruction encodings:
 *   NOP = 0xd503201f  |  RET = 0xd65f03c0
 *   BL  = 0x94000000 | (imm26 & 0x03FFFFFF)
 *
 * Usage:
 *   frida -U -f <package> -l universal_bypass.js --no-pause
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════════
//  LOGGING
// ═══════════════════════════════════════════════════════════════════════════════

function _log(prefix, msg) { console.log(prefix + " " + msg); }
function logBypass(msg)  { _log("[+] BYPASS:", msg); }
function logInfo(msg)    { _log("[*] INFO:", msg); }
function logError(msg)   { _log("[!] ERROR:", msg); }

// ═══════════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

var ROOT_FRAGMENTS = [
    "su", "magisk", "supersu", "daemonsu", "zygisk",
    "busybox", "titanium", "substrate", "xposed",
    "lsposed", "edxposed", "riru",
    "/sbin/su", "/data/local/tmp",
];

var FRIDA_FRAGMENTS = [
    "frida", "gum-js", "gmain", "linjector",
    "re.frida.server", "frida-agent", "frida-gadget",
    "agent.so", "frida-server",
];

var MAPS_FILTER = [
    "frida", "gum-js", "re.frida", "agent.so",
    "linjector", "gmain", "gadget",
    "memfd:frida", "memfd:jit-cache",
    "/data/local/tmp",
];

var RASP_LIBS = [
    "libvkey", "libmos", "libpromon", "libshield",
    "libAppSealing", "libzim", "libtalsec",
    "libDexGuard", "libguard", "libsecure",
];

// ARM64
var ARM64_NOP = 0xd503201f;
var ARM64_RET = 0xd65f03c0;

// V-Key target
var CRASH_OFFSET = 0x66ff4;
var SCAN_WINDOW  = 4096;
var VKEY_NAMES   = ["libvosWrapperEx.so", "libvosWrapper.so", "vosWrapperEx"];

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

function resolveExport(name) {
    try {
        var p = Module.findExportByName(null, name);
        if (p !== null && !p.isNull()) return p;
    } catch (e) { }
    try {
        var libc = Process.findModuleByName("libc.so");
        if (libc) {
            var p = libc.findExportByName(name);
            if (p !== null && !p.isNull()) return p;
        }
    } catch (e) { }
    try {
        var libdl = Process.findModuleByName("libdl.so");
        if (libdl) {
            var p = libdl.findExportByName(name);
            if (p !== null && !p.isNull()) return p;
        }
    } catch (e) { }
    return null;
}

function containsAny(str, fragments) {
    if (!str) return false;
    var lower = str.toLowerCase();
    for (var i = 0; i < fragments.length; i++) {
        if (lower.indexOf(fragments[i].toLowerCase()) !== -1) return true;
    }
    return false;
}

function isVKeyPath(path) {
    if (!path) return false;
    return path.indexOf("vosWrapper") !== -1 || path.indexOf("libvos") !== -1;
}

function findVKeyModule() {
    for (var i = 0; i < VKEY_NAMES.length; i++) {
        var m = Process.findModuleByName(VKEY_NAMES[i]);
        if (m) return m;
    }
    return null;
}

var _hookCount = 0;
var _myPid = Process.id;

function safeAttach(name, callbacks) {
    var p = resolveExport(name);
    if (!p) {
        logError(name + " -- NOT FOUND");
        return false;
    }
    try {
        Interceptor.attach(p, callbacks);
        _hookCount++;
        return true;
    } catch (e) {
        logError(name + " -- attach failed: " + e);
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MEMORY PATCHING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

var _patchedAddrs = {};

function writeNop(addr) {
    var key = addr.toString();
    if (_patchedAddrs[key]) return false;
    try {
        Memory.patchCode(addr, 4, function (code) { code.writeU32(ARM64_NOP); });
        _patchedAddrs[key] = true;
        return true;
    } catch (e) {
        logError("[PATCH] NOP failed @ " + addr + ": " + e);
        return false;
    }
}

function writeRet(addr) {
    var key = addr.toString();
    if (_patchedAddrs[key]) return false;
    try {
        Memory.patchCode(addr, 4, function (code) { code.writeU32(ARM64_RET); });
        _patchedAddrs[key] = true;
        return true;
    } catch (e) {
        logError("[PATCH] RET failed @ " + addr + ": " + e);
        return false;
    }
}

// Scan ARM64 code for BL instructions targeting a specific address.
// ARM64 BL: 0x94000000 | imm26   where imm26 = (target - pc) >> 2 (signed)
function scanAndNopBL(baseAddr, size, targetAddr) {
    var count = 0;
    var n = Math.floor(size / 4);
    for (var i = 0; i < n; i++) {
        var pc = baseAddr.add(i * 4);
        try {
            var instr = pc.readU32();
            if ((instr & 0xFC000000) !== 0x94000000) continue;
            var imm26 = instr & 0x03FFFFFF;
            if (imm26 & 0x02000000) imm26 -= 0x04000000; // sign-extend
            if (pc.add(imm26 * 4).equals(targetAddr)) {
                if (writeNop(pc)) {
                    count++;
                    logBypass("[PATCH] NOP'd BL @ " + pc +
                        " (+" + pc.sub(baseAddr).toString(16) + ")");
                }
            }
        } catch (e) { break; }
    }
    return count;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. BINARY LOBOTOMY — Three-pass patch of libvosWrapperEx.so
//
//  Now callable from THREE hook points (mmap, call_constructors, dlopen).
//  Idempotent: _lobotomized flag prevents double-patching.
// ═══════════════════════════════════════════════════════════════════════════════

var _lobotomized     = false;
var _crashPatched    = false;   // just the single RET at 0x66ff4

function patchCrashSite(mod) {
    if (_crashPatched) return true;
    var addr = mod.base.add(CRASH_OFFSET);
    logBypass("[CRASH-SITE] Writing RET at " + addr +
        " (" + mod.name + " + 0x" + CRASH_OFFSET.toString(16) + ")");
    if (writeRet(addr)) {
        _crashPatched = true;
        logBypass("[CRASH-SITE] SUCCESS — detection function killed");
        return true;
    }
    logError("[CRASH-SITE] FAILED to write RET at " + addr);
    return false;
}

function lobotomize(mod) {
    if (_lobotomized) return;

    var abortAddr = resolveExport("abort");
    var exitAddr  = resolveExport("exit");
    var _exitAddr = resolveExport("_exit");

    logBypass("=== BINARY LOBOTOMY === " + mod.name +
        " base=" + mod.base + " size=" + mod.size);

    // Pass 1: RET at crash site (may already be done by mmap/call_ctors hook)
    patchCrashSite(mod);

    // Pass 2: NOP BL→abort/exit in ±4KB neighborhood
    var windowStart = Math.max(0, CRASH_OFFSET - SCAN_WINDOW);
    var windowEnd   = Math.min(mod.size, CRASH_OFFSET + SCAN_WINDOW);
    var windowBase  = mod.base.add(windowStart);
    var windowSize  = windowEnd - windowStart;

    var localCount = 0;
    if (abortAddr) localCount += scanAndNopBL(windowBase, windowSize, abortAddr);
    if (exitAddr)  localCount += scanAndNopBL(windowBase, windowSize, exitAddr);
    if (_exitAddr) localCount += scanAndNopBL(windowBase, windowSize, _exitAddr);
    logBypass("[PASS 2] NOP'd " + localCount + " BL→abort/exit in ±4KB zone");

    // Pass 3: Full module sweep
    var fullCount = 0;
    if (abortAddr) fullCount += scanAndNopBL(mod.base, mod.size, abortAddr);
    if (exitAddr)  fullCount += scanAndNopBL(mod.base, mod.size, exitAddr);
    if (_exitAddr) fullCount += scanAndNopBL(mod.base, mod.size, _exitAddr);
    logBypass("[PASS 3] NOP'd " + fullCount + " additional BL→abort/exit in full module");

    _lobotomized = true;
    logBypass("[LOBOTOMY] COMPLETE — " +
        (1 + localCount + fullCount) + " instructions rewritten");
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. PRE-EMPTIVE STRIKE — Three methods to patch before constructors
//
//  Method A: Hook linker's call_constructors (best — fires right before ctors)
//  Method B: Hook mmap via fd tracking (fastest — fires at segment mapping)
//  Method C: dlopen onLeave (safety net — fires after ctors, too late alone)
// ═══════════════════════════════════════════════════════════════════════════════

var _targetFds = {};   // fd (int) → true, for tracked fds of target .so

// ── Method A: Hook linker's call_constructors ────────────────────────────────

function hookCallConstructors() {
    var linker = Process.findModuleByName("linker64")
              || Process.findModuleByName("linker");
    if (!linker) { logError("[PRE-A] Linker module not found"); return false; }

    var ctorAddr = null;
    var ctorName = "";

    // Search exports for call_constructors
    try {
        var exports = linker.enumerateExports();
        for (var i = 0; i < exports.length; i++) {
            var n = exports[i].name;
            if (n.indexOf("call_constructor") !== -1 && exports[i].type === "function") {
                ctorAddr = exports[i].address;
                ctorName = n;
                break;
            }
        }
    } catch (e) { }

    // Fallback: search all symbols (includes non-exported)
    if (!ctorAddr) {
        try {
            var symbols = linker.enumerateSymbols();
            for (var i = 0; i < symbols.length; i++) {
                var n = symbols[i].name;
                if (n.indexOf("call_constructor") !== -1
                    && symbols[i].address && !symbols[i].address.isNull()) {
                    ctorAddr = symbols[i].address;
                    ctorName = n;
                    break;
                }
            }
        } catch (e) { }
    }

    if (!ctorAddr) {
        logError("[PRE-A] call_constructors not found in " + linker.name);
        // Log what IS available for debugging
        try {
            var exports = linker.enumerateExports();
            var interesting = [];
            for (var i = 0; i < exports.length; i++) {
                var n = exports[i].name;
                if (n.indexOf("soinfo") !== -1 || n.indexOf("constructor") !== -1
                    || n.indexOf("init_func") !== -1 || n.indexOf("DT_INIT") !== -1) {
                    interesting.push(n);
                }
            }
            if (interesting.length > 0) {
                logInfo("[PRE-A] Possibly related linker symbols:");
                for (var i = 0; i < Math.min(interesting.length, 10); i++) {
                    logInfo("  " + interesting[i]);
                }
            }
        } catch (e) { }
        return false;
    }

    logBypass("[PRE-A] Found: " + ctorName + " @ " + ctorAddr);

    Interceptor.attach(ctorAddr, {
        onEnter: function () {
            if (_crashPatched) return;
            // call_constructors fires for every .so. Check if our target is mapped.
            var mod = findVKeyModule();
            if (mod) {
                logBypass("[PRE-A] TARGET IN MEMORY — patching before constructors!");
                patchCrashSite(mod);
                // Full lobotomy too — we're still before this module's ctors
                if (!_lobotomized) lobotomize(mod);
            }
        }
    });

    _hookCount++;
    logBypass("[PRE-A] call_constructors hook INSTALLED");
    return true;
}

// ── Method B: Hook mmap to catch the instant .text is mapped ────────────────

function hookMmapMonitor() {
    // The linker has its own mmap — try to find it
    var linker = Process.findModuleByName("linker64")
              || Process.findModuleByName("linker");
    var mmapAddr = null;
    var mmapSource = "";

    if (linker) {
        try {
            var exports = linker.enumerateExports();
            for (var i = 0; i < exports.length; i++) {
                var n = exports[i].name;
                // Look for mmap variants in the linker
                if ((n === "__dl_mmap" || n === "__dl_mmap64"
                     || n.indexOf("mmap") !== -1)
                    && exports[i].type === "function"
                    && n.indexOf("munmap") === -1) {
                    mmapAddr = exports[i].address;
                    mmapSource = "linker:" + n;
                    break;
                }
            }
        } catch (e) { }
    }

    // Fallback: libc mmap (may miss linker-internal mmap calls)
    if (!mmapAddr) {
        mmapAddr = Module.findExportByName("libc.so", "mmap64")
                || Module.findExportByName("libc.so", "mmap");
        mmapSource = "libc:mmap";
    }

    if (!mmapAddr) {
        logError("[PRE-B] No mmap found");
        return false;
    }

    // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
    Interceptor.attach(mmapAddr, {
        onEnter: function (args) {
            this._fd     = args[4].toInt32();
            this._len    = args[1].toUInt32();
            this._offset = args[5].toUInt32();
        },
        onLeave: function (retval) {
            if (_crashPatched) return;

            // Quick rejects
            if (retval.isNull()) return;
            var retInt = retval.toInt32();
            if (retInt === -1 || retInt === 0) return;  // MAP_FAILED or NULL
            if (this._fd < 0 || !_targetFds[this._fd]) return;

            // Check if CRASH_OFFSET falls in [file_offset, file_offset + length)
            var fOff = this._offset;
            var fLen = this._len;
            if (CRASH_OFFSET >= fOff && CRASH_OFFSET < fOff + fLen) {
                var crashMem = retval.add(CRASH_OFFSET - fOff);
                logBypass("[PRE-B] mmap caught target .text — crash site at " + crashMem);

                if (writeRet(crashMem)) {
                    _crashPatched = true;
                    logBypass("[PRE-B] SUCCESS — RET written via mmap hook (BEFORE constructors!)");
                } else {
                    logError("[PRE-B] mmap patch failed — relying on Method A/C");
                }
            }
        }
    });

    _hookCount++;
    logBypass("[PRE-B] mmap monitor via " + mmapSource + " INSTALLED");
    return true;
}

// ── fd tracking: openat hook extension (shared with MemFD Phantom) ──────────
// Integrated into the openat hook in §4 — see hookFileSystem().

// ── Method C: dlopen safety net ─────────────────────────────────────────────

function hookLinker() {
    ["dlopen", "android_dlopen_ext"].forEach(function (sym) {
        var p = resolveExport(sym);
        if (!p) return;
        try {
            Interceptor.attach(p, {
                onEnter: function (args) {
                    this.lib = null;
                    this.isVKey = false;
                    this.raspLib = null;
                    try { this.lib = args[0].isNull() ? null : args[0].readUtf8String(); }
                    catch (e) { return; }
                    if (!this.lib) return;
                    logInfo(sym + "() -> " + this.lib);

                    if (isVKeyPath(this.lib)) this.isVKey = true;
                    if (containsAny(this.lib, RASP_LIBS)) this.raspLib = this.lib;
                },
                onLeave: function (retval) {
                    if (!this.lib || retval.isNull()) return;

                    // Refresh phantom maps after any /data/ library loads
                    if (this.lib.indexOf("/data/") !== -1) {
                        try { refreshBuffers(); } catch (e) { }
                    }

                    // ── METHOD C: LOBOTOMY TRIGGER ────────────────────────
                    if (this.isVKey) {
                        if (!_crashPatched) {
                            logError("[PRE-C] Methods A & B missed! Patching in dlopen onLeave (LATE!)");
                        } else {
                            logBypass("[PRE-C] Crash site was already patched BEFORE constructors");
                        }

                        if (!_lobotomized) {
                            var mod = findVKeyModule();
                            if (mod) {
                                lobotomize(mod);
                            } else {
                                // Try by raw name
                                var parts = this.lib.split("/");
                                var modName = parts[parts.length - 1];
                                var m2 = Process.findModuleByName(modName);
                                if (m2) lobotomize(m2);
                            }
                        }
                    }

                    // Block JNI_OnLoad for RASP libs
                    if (this.raspLib) {
                        try {
                            var parts = this.raspLib.split("/");
                            var mn = parts[parts.length - 1];
                            var mod = Process.findModuleByName(mn);
                            if (mod) {
                                var jni = mod.findExportByName("JNI_OnLoad");
                                if (jni && !jni.isNull()) {
                                    Interceptor.replace(jni, new NativeCallback(function () {
                                        logBypass("JNI_OnLoad blocked: " + mn);
                                        return 0x00010006;
                                    }, "int", ["pointer", "pointer"]));
                                }
                            }
                        } catch (e) { }
                    }
                }
            });
            _hookCount++;
        } catch (e) { }
    });

    safeAttach("dlsym", {
        onEnter: function (args) {
            this.block = false;
            try {
                var n = args[1].readUtf8String();
                if (n && containsAny(n, ["frida", "gum_", "gum-", "interceptor", "gadget",
                    "frida_agent", "frida_gadget", "gumjs"])) {
                    this.block = true;
                }
            } catch (e) { }
        },
        onLeave: function (r) { if (this.block) r.replace(ptr(0)); }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. NATIVE FUNCTION SETUP — memfd / pipe / errno
// ═══════════════════════════════════════════════════════════════════════════════

var _nativeClose = null;
var _nativeWrite = null;
var _nativeLseek = null;
var _nativePipe  = null;
var _errnoFn = null;
var _memfdAvailable = false;
var _NR_memfd_create = 0;
var _memfdFn = null;

function initNativeFunctions() {
    var pClose   = resolveExport("close");
    var pWrite   = resolveExport("write");
    var pLseek   = resolveExport("lseek");
    var pPipe    = resolveExport("pipe");
    var pSyscall = resolveExport("syscall");
    var pErrno   = resolveExport("__errno") || resolveExport("__errno_location");

    if (pClose)  _nativeClose = new NativeFunction(pClose, "int", ["int"]);
    if (pWrite)  _nativeWrite = new NativeFunction(pWrite, "long", ["int", "pointer", "long"]);
    if (pLseek)  _nativeLseek = new NativeFunction(pLseek, "long", ["int", "long", "int"]);
    if (pPipe)   _nativePipe  = new NativeFunction(pPipe, "int", ["pointer"]);
    if (pErrno)  _errnoFn     = new NativeFunction(pErrno, "pointer", []);

    if (Process.arch === "arm64")     _NR_memfd_create = 279;
    else if (Process.arch === "arm")  _NR_memfd_create = 385;
    else if (Process.arch === "x64")  _NR_memfd_create = 319;
    else if (Process.arch === "ia32") _NR_memfd_create = 356;

    if (pSyscall && _NR_memfd_create) {
        try {
            _memfdFn = new NativeFunction(pSyscall, "int", ["int", "pointer", "uint"]);
            var testName = Memory.allocUtf8String("");
            var testFd = _memfdFn(_NR_memfd_create, testName, 0);
            if (testFd >= 0) {
                _nativeClose(testFd);
                _memfdAvailable = true;
                logBypass("memfd_create OK (nr=" + _NR_memfd_create + ")");
            } else {
                logInfo("memfd_create returned " + testFd + " — pipe fallback");
            }
        } catch (e) {
            logInfo("memfd_create test failed — pipe fallback");
        }
    }
    if (!_memfdAvailable && _nativePipe) logBypass("Pipe fallback ready");
}

function setErrno(val) {
    if (_errnoFn) { try { _errnoFn().writeS32(val); } catch (e) { } }
}

function createFdWithContent(content) {
    if (!content || content.length === 0) return -1;
    var buf = Memory.allocUtf8String(content);
    var len = content.length;

    if (_memfdAvailable && _memfdFn && _nativeWrite && _nativeLseek) {
        var name = Memory.allocUtf8String("");
        var fd = _memfdFn(_NR_memfd_create, name, 0);
        if (fd >= 0) {
            _nativeWrite(fd, buf, len);
            _nativeLseek(fd, 0, 0);
            return fd;
        }
    }
    if (_nativePipe && _nativeWrite && _nativeClose) {
        var fds = Memory.alloc(8);
        if (_nativePipe(fds) === 0) {
            var r = fds.readS32();
            var w = fds.add(4).readS32();
            _nativeWrite(w, buf, len);
            _nativeClose(w);
            return r;
        }
    }
    return -1;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  4. MEMFD PHANTOM + FILE SYSTEM CAMOUFLAGE
//     Combined: openat also tracks target .so fds for the pre-emptive strike.
// ═══════════════════════════════════════════════════════════════════════════════

var _cleanMaps = "";
var _cleanStatus = "";
var _mapsReady = false;
var _statusReady = false;
var _isRefreshing = false;

function isProcMaps(path) {
    var m = path.match(/\/proc\/(\d+|self)(\/task\/\d+)?\/maps$/);
    if (!m) return false;
    return m[1] === "self" || parseInt(m[1]) === _myPid;
}

function isProcStatus(path) {
    var m = path.match(/\/proc\/(\d+|self)(\/task\/\d+)?\/status$/);
    if (!m) return false;
    return m[1] === "self" || parseInt(m[1]) === _myPid;
}

function refreshBuffers() {
    _isRefreshing = true;
    try {
        var raw = File.readAllText("/proc/self/maps");
        var lines = raw.split("\n");
        var clean = [];
        for (var i = 0; i < lines.length; i++) {
            if (lines[i].length > 0 && containsAny(lines[i], MAPS_FILTER)) continue;
            clean.push(lines[i]);
        }
        _cleanMaps = clean.join("\n");
        _mapsReady = true;
    } catch (e) { }
    try {
        var raw = File.readAllText("/proc/self/status");
        _cleanStatus = raw.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
        _statusReady = true;
    } catch (e) { }
    _isRefreshing = false;
}

function initPhantom() {
    refreshBuffers();
    logBypass("MemFD Phantom: maps=" + _cleanMaps.length + "B status=" + _cleanStatus.length + "B");
    setInterval(function () { try { refreshBuffers(); } catch (e) { } }, 5000);
}

function hookFileSystem() {

    // Shared handler for open/openat onEnter
    function handleOpenEnter(path) {
        this.block = false;
        this.redirect = 0;
        this.trackFd = false;

        if (!path) return;

        // Pre-emptive strike: track target .so fds
        if (isVKeyPath(path)) {
            this.trackFd = true;
        }

        // MemFD phantom redirects
        if (_isRefreshing) return;
        if (path.indexOf("/proc/") !== -1) {
            if (isProcMaps(path))   { this.redirect = 1; return; }
            if (isProcStatus(path)) { this.redirect = 2; return; }
            return;
        }

        // Block root/frida file access
        if (containsAny(path, ROOT_FRAGMENTS) || containsAny(path, FRIDA_FRAGMENTS))
            this.block = true;
    }

    function handleOpenLeave(retval) {
        var fd = retval.toInt32();

        // Track target .so fd for mmap monitoring
        if (this.trackFd && fd >= 0) {
            _targetFds[fd] = true;
            logBypass("[FD-TRACK] Target .so opened, fd=" + fd);
        }

        if (this.block) { retval.replace(-1); setErrno(2); return; }
        if (this.redirect > 0 && fd >= 0) {
            var c = (this.redirect === 1) ? _cleanMaps : _cleanStatus;
            var r = (this.redirect === 1) ? _mapsReady : _statusReady;
            if (r && c.length > 0) {
                var newFd = createFdWithContent(c);
                if (newFd >= 0) {
                    if (_nativeClose) _nativeClose(fd);
                    retval.replace(newFd);
                }
            }
        }
    }

    // ── open() ───────────────────────────────────────────────────────────
    safeAttach("open", {
        onEnter: function (args) {
            try { this._path = args[0].readUtf8String(); } catch (e) { this._path = null; }
            handleOpenEnter.call(this, this._path);
        },
        onLeave: function (retval) { handleOpenLeave.call(this, retval); }
    });

    // ── openat() ─────────────────────────────────────────────────────────
    safeAttach("openat", {
        onEnter: function (args) {
            try { this._path = args[1].readUtf8String(); } catch (e) { this._path = null; }
            handleOpenEnter.call(this, this._path);
        },
        onLeave: function (retval) { handleOpenLeave.call(this, retval); }
    });

    // ── faccessat ────────────────────────────────────────────────────────
    safeAttach("faccessat", {
        onEnter: function (args) {
            this.block = false;
            try {
                var p = args[1].readUtf8String();
                if (p && (containsAny(p, ROOT_FRAGMENTS) || containsAny(p, FRIDA_FRAGMENTS)))
                    this.block = true;
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.block) { retval.replace(-1); setErrno(2); }
        }
    });

    // ── stat / lstat variants ────────────────────────────────────────────
    var sc = 0;
    ["stat", "lstat", "stat64", "lstat64", "__stat64_time64", "__lstat64_time64"]
        .forEach(function (sym) {
            var p = resolveExport(sym);
            if (!p) return;
            try {
                Interceptor.attach(p, {
                    onEnter: function (args) {
                        this.block = false;
                        try {
                            var path = args[0].readUtf8String();
                            if (path && containsAny(path, ROOT_FRAGMENTS)) this.block = true;
                        } catch (e) { }
                    },
                    onLeave: function (retval) {
                        if (this.block) { retval.replace(-1); setErrno(2); }
                    }
                });
                sc++;
            } catch (e) { }
        });
    logBypass("stat/lstat: " + sc + " variants hooked");

    // ── access ───────────────────────────────────────────────────────────
    safeAttach("access", {
        onEnter: function (args) {
            this.block = false;
            try {
                var p = args[0].readUtf8String();
                if (p && (containsAny(p, ROOT_FRAGMENTS) || containsAny(p, FRIDA_FRAGMENTS)))
                    this.block = true;
            } catch (e) { }
        },
        onLeave: function (retval) {
            if (this.block) { retval.replace(-1); setErrno(2); }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  5. STRING NEUTRALIZER — strstr / strcmp / strncmp
// ═══════════════════════════════════════════════════════════════════════════════

function hookStringOps() {
    var POISON = [
        "frida", "xposed", "substrate", "magisk", "supersu",
        "gum-js", "linjector", "re.frida", "gadget",
        "frida-server", "frida-agent", "frida-gadget", "REJECT",
    ];

    safeAttach("strstr", {
        onEnter: function (a) {
            this.block = false;
            try { var n = a[1].readUtf8String(); if (n && containsAny(n, POISON)) this.block = true; } catch (e) { }
        },
        onLeave: function (r) { if (this.block) r.replace(ptr(0)); }
    });
    safeAttach("strcmp", {
        onEnter: function (a) {
            this.block = false;
            try {
                var s1 = a[0].readUtf8String(), s2 = a[1].readUtf8String();
                if ((s1 && containsAny(s1, POISON)) || (s2 && containsAny(s2, POISON))) this.block = true;
            } catch (e) { }
        },
        onLeave: function (r) { if (this.block) r.replace(1); }
    });
    safeAttach("strncmp", {
        onEnter: function (a) {
            this.block = false;
            try {
                var s1 = a[0].readUtf8String(), s2 = a[1].readUtf8String();
                if ((s1 && containsAny(s1, POISON)) || (s2 && containsAny(s2, POISON))) this.block = true;
            } catch (e) { }
        },
        onLeave: function (r) { if (this.block) r.replace(1); }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  6. SUICIDE PREVENTION — Auto-NOP Edition
// ═══════════════════════════════════════════════════════════════════════════════

var _abortTraced = false;
var _abortCount = 0;
var _exitCount = 0;

function nopCallSite(retAddr) {
    var bl = retAddr.sub(4);
    try {
        var instr = bl.readU32();
        if ((instr & 0xFC000000) === 0x94000000) {
            if (writeNop(bl)) {
                var mod = Process.findModuleByAddress(bl);
                var info = mod ? (mod.name + "+0x" + bl.sub(mod.base).toString(16)) : bl.toString();
                logBypass("[AUTO-NOP] Patched call site: " + info);
                return true;
            }
        }
    } catch (e) { }
    return false;
}

function hookSuicidePrevention() {

    // ── ptrace ───────────────────────────────────────────────────────────
    safeAttach("ptrace", {
        onEnter: function () { },
        onLeave: function (r) { r.replace(0); }
    });

    // ── abort() — backtrace + auto-NOP ───────────────────────────────────
    var pAbort = resolveExport("abort");
    if (pAbort) {
        try {
            Interceptor.replace(pAbort, new NativeCallback(function () {
                _abortCount++;
                if (!_abortTraced) {
                    _abortTraced = true;
                    logBypass("=== abort() HIT #1 — Native backtrace ===");
                    try {
                        var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
                        for (var i = 0; i < bt.length; i++) {
                            logBypass("  #" + i + "  " + DebugSymbol.fromAddress(bt[i]));
                        }
                        for (var i = 0; i < bt.length; i++) {
                            var mod = Process.findModuleByAddress(bt[i]);
                            if (mod && mod.path.indexOf("/data/app/") !== -1) {
                                nopCallSite(bt[i]);
                            }
                        }
                    } catch (e) { logError("backtrace: " + e); }
                    logBypass("=== end backtrace ===");
                }
                if (_abortCount <= 3)
                    logBypass("abort() SWALLOWED (#" + _abortCount + ")");
            }, "void", []));
            _hookCount++;
            logBypass("abort() replaced (auto-NOP armed)");
        } catch (e) { logError("abort: " + e); }
    }

    // ── exit / _exit ─────────────────────────────────────────────────────
    ["exit", "_exit"].forEach(function (name) {
        var p = resolveExport(name);
        if (!p) return;
        try {
            Interceptor.replace(p, new NativeCallback(function (code) {
                _exitCount++;
                if (_exitCount <= 3)
                    logBypass(name + "(" + code + ") SWALLOWED" +
                        ((code === 106 || code === 107) ? " [V-KEY KILL]" : ""));
            }, "void", ["int"]));
            _hookCount++;
        } catch (e) { }
    });

    // ── kill (self-kill only) ────────────────────────────────────────────
    var pKill = resolveExport("kill");
    if (pKill) {
        try {
            var realKill = new NativeFunction(pKill, "int", ["int", "int"]);
            Interceptor.replace(pKill, new NativeCallback(function (pid, sig) {
                if (pid === Process.id || pid === 0) {
                    logBypass("kill(" + pid + "," + sig + ") BLOCKED");
                    return 0;
                }
                return realKill(pid, sig);
            }, "int", ["int", "int"]));
            _hookCount++;
        } catch (e) { }
    }

    // ── raise ────────────────────────────────────────────────────────────
    var pRaise = resolveExport("raise");
    if (pRaise) {
        try {
            Interceptor.replace(pRaise, new NativeCallback(function (sig) {
                logBypass("raise(" + sig + ") BLOCKED");
                return 0;
            }, "int", ["int"]));
            _hookCount++;
        } catch (e) { }
    }

    // ── sigaction — block SIGABRT/SIGTERM handler registration ───────────
    safeAttach("sigaction", {
        onEnter: function (args) {
            this.block = false;
            var sig = args[0].toInt32();
            if (sig === 6 || sig === 9 || sig === 15) {
                this.block = true;
            }
        },
        onLeave: function (r) { if (this.block) r.replace(0); }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  7. READLINK CONCEALMENT
// ═══════════════════════════════════════════════════════════════════════════════

function hookReadlink() {
    var LINK_POISON = ["frida", "gum-js", "linjector", "gadget"];

    safeAttach("readlink", {
        onEnter: function (a) { this.buf = a[1]; },
        onLeave: function (r) {
            var len = r.toInt32();
            if (len <= 0) return;
            try {
                var t = this.buf.readUtf8String(len);
                if (t && containsAny(t, LINK_POISON)) {
                    this.buf.writeUtf8String("/dev/ashmem");
                    r.replace(11);
                }
            } catch (e) { }
        }
    });

    safeAttach("readlinkat", {
        onEnter: function (a) { this.buf = a[2]; },
        onLeave: function (r) {
            var len = r.toInt32();
            if (len <= 0) return;
            try {
                var t = this.buf.readUtf8String(len);
                if (t && containsAny(t, LINK_POISON)) {
                    this.buf.writeUtf8String("/dev/ashmem");
                    r.replace(11);
                }
            } catch (e) { }
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  8. SYSTEM PROPERTY CAMOUFLAGE — __system_property_get +
//                                   __system_property_read_callback
// ═══════════════════════════════════════════════════════════════════════════════

function hookSysProps() {
    var PROP_SPOOF = {
        // Anti-root
        "ro.debuggable":                  "0",
        "ro.secure":                      "1",
        "ro.build.tags":                  "release-keys",
        "ro.build.type":                  "user",
        "ro.build.selinux":               "1",
        // Hardware attestation / bootloader
        "ro.boot.vbmeta.device_state":    "locked",
        "ro.boot.flash.locked":           "1",
        "ro.boot.verifiedbootstate":      "green",
        "ro.boot.veritymode":             "enforcing",
        "ro.boot.warranty_bit":           "0",
        "ro.warranty_bit":                "0",
        "ro.is_ever_orange":              "0",
        // Emulator detection
        "ro.kernel.qemu":                 "0",
        "ro.hardware.chipname":           "exynos990",
    };

    // ── __system_property_get (classic API) ──────────────────────────────
    safeAttach("__system_property_get", {
        onEnter: function (args) {
            this.name = null;
            this.buf = args[1];
            try { this.name = args[0].readUtf8String(); } catch (e) { }
        },
        onLeave: function () {
            if (this.name && PROP_SPOOF[this.name] !== undefined) {
                this.buf.writeUtf8String(PROP_SPOOF[this.name]);
            }
        }
    });

    // ── __system_property_read_callback (Android 8+ native path) ────────
    // void __system_property_read_callback(
    //     const prop_info *pi,
    //     void (*callback)(void *cookie, const char *name,
    //                      const char *value, uint32_t serial),
    //     void *cookie)
    //
    // The callback is invoked synchronously. We replace args[1] with a
    // wrapper that intercepts the (name, value) pair and spoofs if needed.
    // Thread-safe via per-tid original callback storage.

    var pReadCb = resolveExport("__system_property_read_callback");
    if (pReadCb) {
        var _origCbByTid = {};

        var wrapperCb = new NativeCallback(function (cookie, namePtr, valuePtr, serial) {
            var tid = Process.getCurrentThreadId();
            var origCb = _origCbByTid[tid];
            if (!origCb) return;
            delete _origCbByTid[tid];

            try {
                var name = namePtr.readUtf8String();
                if (name && PROP_SPOOF[name] !== undefined) {
                    var fakeBuf = Memory.allocUtf8String(PROP_SPOOF[name]);
                    origCb(cookie, namePtr, fakeBuf, serial);
                    return;
                }
            } catch (e) { }

            origCb(cookie, namePtr, valuePtr, serial);
        }, "void", ["pointer", "pointer", "pointer", "uint32"]);

        try {
            Interceptor.attach(pReadCb, {
                onEnter: function (args) {
                    var origPtr = args[1];
                    if (origPtr.isNull()) return;
                    var tid = Process.getCurrentThreadId();
                    _origCbByTid[tid] = new NativeFunction(origPtr,
                        "void", ["pointer", "pointer", "pointer", "uint32"]);
                    args[1] = wrapperCb;
                }
            });
            _hookCount++;
            logBypass("__system_property_read_callback hooked (Android 8+ path)");
        } catch (e) {
            logError("__system_property_read_callback: " + e);
        }
    } else {
        logInfo("__system_property_read_callback not found (older Android?)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  9. THREAD STEALTH — Hide Frida thread names
// ═══════════════════════════════════════════════════════════════════════════════

var THREAD_POISON = ["gmain", "gum-js", "gdbus", "frida", "linjector", "pool-frida"];

function hookThreadStealth() {
    var pGetName = resolveExport("pthread_getname_np");
    if (pGetName) {
        try {
            Interceptor.attach(pGetName, {
                onEnter: function (a) { this.buf = a[1]; },
                onLeave: function (r) {
                    if (r.toInt32() !== 0) return;
                    try {
                        var name = this.buf.readUtf8String();
                        if (name && containsAny(name, THREAD_POISON))
                            this.buf.writeUtf8String("binder:" + _myPid);
                    } catch (e) { }
                }
            });
            _hookCount++;
        } catch (e) { }
    }

    var pPrctl = resolveExport("prctl");
    if (pPrctl) {
        try {
            Interceptor.attach(pPrctl, {
                onEnter: function (a) {
                    this.isGet = (a[0].toInt32() === 16); // PR_GET_NAME
                    this.buf = a[1];
                },
                onLeave: function (r) {
                    if (!this.isGet || r.toInt32() !== 0) return;
                    try {
                        var name = this.buf.readUtf8String();
                        if (name && containsAny(name, THREAD_POISON))
                            this.buf.writeUtf8String("binder:" + _myPid);
                    } catch (e) { }
                }
            });
            _hookCount++;
        } catch (e) { }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN — Three-method pre-emptive initialization
// ═══════════════════════════════════════════════════════════════════════════════

(function main() {
    console.log("");
    console.log("================================================================");
    console.log("  Universal Bypass v17 — The Pre-Emptive Strike");
    console.log("================================================================");
    console.log("  Method A: Linker call_constructors hook (pre-constructor)");
    console.log("  Method B: mmap fd-tracking hook (pre-mapping)");
    console.log("  Method C: dlopen onLeave (safety net)");
    console.log("  NO Stalker | NO Java | Interceptor + Memory.patchCode");
    console.log("================================================================");
    console.log("");

    try { initNativeFunctions(); } catch (e) { logError("initNativeFunctions: " + e); }

    logInfo("PID=" + _myPid + " arch=" + Process.arch);

    // ── Pre-Emptive Strike: install all three methods ─────────────────
    logInfo("=== Installing Pre-Emptive Strike ===");
    var methodA = false, methodB = false;
    try { methodA = hookCallConstructors(); } catch (e) { logError("Method A: " + e); }
    try { methodB = hookMmapMonitor(); }      catch (e) { logError("Method B: " + e); }
    logInfo("Strike vectors: A(call_ctors)=" + methodA + " B(mmap)=" + methodB);
    if (!methodA && !methodB) {
        logError("WARNING: Neither Method A nor B available!");
        logError("Falling back to Method C only (dlopen onLeave — may be too late)");
    }

    // ── Standard hooks ─────────────────────────────────────────────────
    logInfo("=== Installing standard hooks ===");
    try { initPhantom(); }           catch (e) { logError("phantom: " + e); }
    try { hookFileSystem(); }        catch (e) { logError("fs: " + e); }
    try { hookStringOps(); }         catch (e) { logError("str: " + e); }
    try { hookSuicidePrevention(); } catch (e) { logError("suicide: " + e); }
    try { hookLinker(); }            catch (e) { logError("linker: " + e); }
    try { hookReadlink(); }          catch (e) { logError("readlink: " + e); }
    try { hookSysProps(); }          catch (e) { logError("props: " + e); }
    try { hookThreadStealth(); }     catch (e) { logError("stealth: " + e); }

    logInfo(_hookCount + " Interceptor hooks installed");

    // ── Late-attach: if V-Key already loaded, lobotomize now ──────────
    var existing = findVKeyModule();
    if (existing && !_lobotomized) {
        logBypass("[LATE-ATTACH] V-Key already in memory — lobotomizing now");
        patchCrashSite(existing);
        lobotomize(existing);
    }

    console.log("");
    logInfo("v17 Pre-Emptive Strike LIVE.");
    logInfo("  Target: " + VKEY_NAMES[0] + " offset 0x" + CRASH_OFFSET.toString(16));
    logInfo("  Patch window: mmap -> call_constructors -> dlopen");
    logInfo("  Waiting for target to load...");
    console.log("");
})();
