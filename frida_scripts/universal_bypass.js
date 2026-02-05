/*
 * Universal Bypass — SSL Pinning + Root Detection + Runtime Tampering
 *
 * Single script that combines:
 *   1. SSL Pinning Bypass (TrustManager, OkHttp, Conscrypt, WebView, Flutter)
 *   2. Root Detection Bypass (file checks, packages, properties, native access)
 *   3. Runtime Tampering Bypass (anti-Frida, anti-debug, integrity checks)
 *
 * Every hook is wrapped in try/catch to prevent crashes.
 * Unique class names use timestamps to prevent collision on reload.
 *
 * Usage:
 *   frida -U -f <package> -l universal_bypass.js
 *   frida -U <package> -l universal_bypass.js
 */

var Color = {
    RED:    '\x1b[31m',
    GREEN:  '\x1b[32m',
    YELLOW: '\x1b[33m',
    CYAN:   '\x1b[36m',
    RESET:  '\x1b[0m',
    BOLD:   '\x1b[1m',
    DIM:    '\x1b[2m'
};

var _uid = Date.now();

function log(tag, msg) {
    var colors = {
        'SSL':     Color.GREEN,
        'ROOT':    Color.CYAN,
        'TAMPER':  Color.YELLOW,
        'ERROR':   Color.RED
    };
    var c = colors[tag] || Color.RESET;
    console.log(c + Color.BOLD + '[' + tag + ']' + Color.RESET + ' ' + msg);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. SSL PINNING BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassSSL() {

    // ── Custom TrustManager that trusts all certificates ────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.bypass.TrustManager_' + _uid,
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) { },
                checkServerTrusted: function (chain, authType) { },
                getAcceptedIssuers: function () { return []; }
            }
        });
        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, Java.use('java.security.SecureRandom').$new());
        SSLContext.getInstance.overload('java.lang.String').implementation = function (protocol) {
            var ctx = this.getInstance(protocol);
            ctx.init(null, TrustManagers, Java.use('java.security.SecureRandom').$new());
            return ctx;
        };
        log('SSL', 'Custom TrustManager installed (trusts all certs)');
    } catch (e) {
        log('ERROR', 'TrustManager: ' + e);
    }

    // ── TrustManagerFactory — return our TrustManager ───────────────────
    try {
        var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        var tmfUid = _uid;
        TrustManagerFactory.getTrustManagers.implementation = function () {
            var X509TM = Java.use('javax.net.ssl.X509TrustManager');
            var fakeTM = Java.registerClass({
                name: 'com.bypass.FakeTMF_' + tmfUid + '_' + this.hashCode(),
                implements: [X509TM],
                methods: {
                    checkClientTrusted: function () { },
                    checkServerTrusted: function () { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            return [fakeTM.$new()];
        };
        log('SSL', 'TrustManagerFactory.getTrustManagers hooked');
    } catch (e) {
        log('ERROR', 'TrustManagerFactory: ' + e);
    }

    // ── HostnameVerifier — accept all hostnames ─────────────────────────
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAll = Java.registerClass({
            name: 'com.bypass.AllHostsVerifier_' + _uid,
            implements: [HostnameVerifier],
            methods: {
                verify: function () { return true; }
            }
        });
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier(AllowAll.$new());
        HttpsURLConnection.setHostnameVerifier.implementation = function (v) {
            return;
        };
        log('SSL', 'HostnameVerifier set to accept all');
    } catch (e) {
        log('ERROR', 'HostnameVerifier: ' + e);
    }

    // ── OkHttp3 CertificatePinner ───────────────────────────────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', 'java.util.List').implementation = function () { };
        log('SSL', 'OkHttp3 CertificatePinner.check bypassed');
    } catch (e) { /* OkHttp3 not present */ }

    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        CertPinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function () { };
    } catch (e) { /* overload not present */ }

    // ── OkHttp3 check$okhttp (proguarded / newer versions) ─────────────
    try {
        var CertPinner = Java.use('okhttp3.CertificatePinner');
        if (CertPinner['check$okhttp'] !== undefined) {
            CertPinner['check$okhttp'].implementation = function () { };
            log('SSL', 'OkHttp3 check$okhttp bypassed');
        }
    } catch (e) { /* not present */ }

    // ── OkHttp3 CertificatePinner$Builder — empty pinning ──────────────
    try {
        var Builder = Java.use('okhttp3.CertificatePinner$Builder');
        Builder.add.implementation = function (hostname) {
            return this;
        };
        log('SSL', 'OkHttp3 CertificatePinner.Builder.add bypassed');
    } catch (e) { /* not present */ }

    // ── OkHttp3 proguarded pinner (scan for pin-checking classes) ───────
    try {
        // Find classes that have a 'check' method taking String + List
        // and a field named 'pins' or similar — common obfuscated pattern
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                // Only scan likely obfuscated short names
                if (className.length > 3 && className.length < 15 && className.indexOf('.') !== -1) {
                    try {
                        var cls = Java.use(className);
                        // Check for CertificatePinner-like method signatures
                        if (cls.check !== undefined) {
                            var overloads = cls.check.overloads;
                            for (var i = 0; i < overloads.length; i++) {
                                var params = overloads[i].argumentTypes;
                                if (params.length === 2 &&
                                    params[0].className === 'java.lang.String' &&
                                    params[1].className === 'java.util.List') {
                                    overloads[i].implementation = function () { };
                                    log('SSL', 'Proguarded pinner bypassed: ' + className + '.check()');
                                }
                            }
                        }
                    } catch (e) { /* skip */ }
                }
            },
            onComplete: function () { }
        });
    } catch (e) { /* not critical */ }

    // ── Appmattus CertificateTransparency ───────────────────────────────
    try {
        var CTInterceptor = Java.use('com.appmattus.certificatetransparency.internal.CertificateTransparencyInterceptor');
        CTInterceptor.intercept.implementation = function (chain) {
            return chain.proceed(chain.request());
        };
        log('SSL', 'Appmattus CertificateTransparency bypassed');
    } catch (e) { /* not present */ }

    // ── TrustKit ────────────────────────────────────────────────────────
    try {
        var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKit.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () { return true; };
        TrustKit.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function () { return true; };
        log('SSL', 'TrustKit OkHostnameVerifier bypassed');
    } catch (e) { /* not present */ }

    // ── Conscrypt (modern TLS provider) ─────────────────────────────────
    try {
        var Platform = Java.use('com.android.org.conscrypt.Platform');
        Platform.checkServerTrusted.overload('javax.net.ssl.X509TrustManager', '[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'com.android.org.conscrypt.AbstractConscryptSocket').implementation = function () { };
        log('SSL', 'Conscrypt Platform.checkServerTrusted bypassed');
    } catch (e) { /* not present */ }

    try {
        var ConscryptTM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        ConscryptTM.verifyChain.implementation = function (untrusted) {
            return untrusted;
        };
        log('SSL', 'Conscrypt TrustManagerImpl.verifyChain bypassed');
    } catch (e) { /* not present */ }

    // ── Android WebView SSL errors ──────────────────────────────────────
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
            handler.proceed();
        };
        log('SSL', 'WebViewClient.onReceivedSslError — auto-proceed');
    } catch (e) {
        log('ERROR', 'WebViewClient SSL: ' + e);
    }

    // ── AbstractVerifier (Apache HTTP legacy) ───────────────────────────
    try {
        var AbstractVerifier = Java.use('org.apache.http.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean').implementation = function () { };
        log('SSL', 'Apache AbstractVerifier bypassed');
    } catch (e) { /* not present */ }

    // ── Flutter/Dart SSL (via BoringSSL native hook) ────────────────────
    try {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            if (modules[i].name.indexOf('libflutter') !== -1) {
                var exports = modules[i].enumerateExports();
                for (var j = 0; j < exports.length; j++) {
                    if (exports[j].name.indexOf('ssl_crypto_x509_session_verify_cert_chain') !== -1 ||
                        exports[j].name.indexOf('session_verify_cert_chain') !== -1) {
                        Interceptor.attach(exports[j].address, {
                            onLeave: function (retval) { retval.replace(0x1); }
                        });
                        log('SSL', 'Flutter BoringSSL bypassed (' + exports[j].name + ')');
                    }
                }
            }
        }
    } catch (e) { /* Flutter not present */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. ROOT DETECTION BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassRoot() {

    var rootPaths = [
        '/system/app/Superuser.apk', '/system/app/Superuser', '/system/app/SuperSU',
        '/system/xbin/su', '/system/bin/su', '/sbin/su', '/su/bin/su',
        '/data/local/su', '/data/local/bin/su', '/data/local/xbin/su',
        '/system/bin/.ext/.su', '/system/etc/.has_su_daemon',
        '/system/usr/we-need-root/', '/cache/su',
        '/data/su', '/dev/su', '/system/sd/xbin/su',
        '/system/xbin/daemonsu', '/system/xbin/busybox',
        '/system/bin/failsafe/su', '/vendor/bin/su',
        '/su/bin', '/su',
        '/data/local/tmp/frida-server', '/data/local/tmp/re.frida.server',
        '/sbin/.magisk', '/sbin/.core', '/data/adb/magisk',
        '/data/adb/magisk.img', '/data/adb/magisk.db',
        '/cache/.disable_magisk', '/dev/.magisk.unblock',
        '/init.magisk.rc',
    ];

    // Build a lookup set for O(1) matching
    var rootPathSet = {};
    for (var i = 0; i < rootPaths.length; i++) {
        rootPathSet[rootPaths[i]] = true;
    }

    var rootPackages = [
        'com.topjohnwu.magisk', 'com.koushikdutta.superuser',
        'com.noshufou.android.su', 'com.thirdparty.superuser',
        'eu.chainfire.supersu', 'com.yellowes.su',
        'com.devadvance.rootcloak', 'com.devadvance.rootcloakplus',
        'de.robv.android.xposed.installer', 'com.saurik.substrate',
        'com.zachspong.temprootremovejb', 'com.amphoras.hidemyroot',
        'com.amphoras.hidemyrootadfree', 'com.formyhm.hiderootPremium',
        'com.formyhm.hideroot', 'com.koushikdutta.rommanager',
        'com.dimonvideo.luckypatcher', 'com.chelpus.lackypatch',
        'com.ramdroid.appquarantine', 'me.phh.superuser',
        'io.github.vvb2060.magisk',
    ];

    var rootPackageSet = {};
    for (var i = 0; i < rootPackages.length; i++) {
        rootPackageSet[rootPackages[i]] = true;
    }

    function isRootPath(path) {
        if (rootPathSet[path]) return true;
        // Catch any path containing /su that isn't sugar/surf/suite/etc
        if (path.indexOf('/su') !== -1) {
            var after = path.substring(path.lastIndexOf('/su') + 3);
            if (after === '' || after[0] === '/' || after[0] === '.') return true;
        }
        return false;
    }

    // ── java.io.File — hide root paths ──────────────────────────────────
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (isRootPath(path)) {
                log('ROOT', 'File.exists("' + path + '") -> false');
                return false;
            }
            return this.exists();
        };
        log('ROOT', 'File.exists hooked (' + rootPaths.length + ' paths hidden)');
    } catch (e) {
        log('ERROR', 'File.exists: ' + e);
    }

    try {
        var File = Java.use('java.io.File');
        File.isDirectory.implementation = function () {
            var path = this.getAbsolutePath();
            if (rootPathSet[path]) return false;
            return this.isDirectory();
        };
    } catch (e) { /* not needed */ }

    // ── PackageManager — hide root packages ─────────────────────────────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (rootPackageSet[pkg]) {
                log('ROOT', 'getPackageInfo("' + pkg + '") -> NameNotFoundException');
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
            }
            return this.getPackageInfo(pkg, flags);
        };
        log('ROOT', 'PackageManager.getPackageInfo hooked (' + rootPackages.length + ' packages hidden)');
    } catch (e) {
        log('ERROR', 'PackageManager: ' + e);
    }

    // ── PackageManager.getInstalledPackages — filter root apps ──────────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledPackages.overload('int').implementation = function (flags) {
            var pkgs = this.getInstalledPackages(flags);
            var it = pkgs.iterator();
            while (it.hasNext()) {
                var info = Java.cast(it.next(), Java.use('android.content.pm.PackageInfo'));
                if (rootPackageSet[info.packageName.value]) {
                    it.remove();
                }
            }
            return pkgs;
        };
        log('ROOT', 'PackageManager.getInstalledPackages filtered');
    } catch (e) { /* not needed */ }

    // ── PackageManager.getInstalledApplications — filter root apps ──────
    try {
        var PM = Java.use('android.app.ApplicationPackageManager');
        PM.getInstalledApplications.overload('int').implementation = function (flags) {
            var apps = this.getInstalledApplications(flags);
            var it = apps.iterator();
            while (it.hasNext()) {
                var info = Java.cast(it.next(), Java.use('android.content.pm.ApplicationInfo'));
                if (rootPackageSet[info.packageName.value]) {
                    it.remove();
                }
            }
            return apps;
        };
        log('ROOT', 'PackageManager.getInstalledApplications filtered');
    } catch (e) { /* not needed */ }

    // ── Runtime.exec — block root commands ──────────────────────────────
    try {
        var Runtime = Java.use('java.lang.Runtime');

        function isRootCmd(cmd) {
            // Only block exact root-probing commands, not legitimate usage
            var blocked = ['which su', '/system/xbin/which su', '/system/bin/which su'];
            for (var i = 0; i < blocked.length; i++) {
                if (cmd.indexOf(blocked[i]) !== -1) return true;
            }
            // Block if the entire command is just 'su' (not 'sudo', 'sum', etc)
            var trimmed = cmd.trim();
            if (trimmed === 'su' || trimmed === 'su -' || trimmed.match(/^su\s+/)) return true;
            return false;
        }

        Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            var cmd = cmds.join(' ');
            if (isRootCmd(cmd)) {
                log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                throw Java.use('java.io.IOException').$new('Cannot run program');
            }
            return this.exec(cmds);
        };
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (isRootCmd(cmd)) {
                log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                throw Java.use('java.io.IOException').$new('Cannot run program');
            }
            return this.exec(cmd);
        };
        Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File').implementation = function (cmd, env, dir) {
            if (isRootCmd(cmd)) {
                log('ROOT', 'Runtime.exec("' + cmd + '") -> IOException');
                throw Java.use('java.io.IOException').$new('Cannot run program');
            }
            return this.exec(cmd, env, dir);
        };
        log('ROOT', 'Runtime.exec hooked (blocking root commands)');
    } catch (e) {
        log('ERROR', 'Runtime.exec: ' + e);
    }

    // ── ProcessBuilder — block root commands ────────────────────────────
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        ProcessBuilder.start.implementation = function () {
            var cmds = this.command();
            var first = cmds.size() > 0 ? String(cmds.get(0)) : '';
            if (first.endsWith('/su') || first === 'su') {
                log('ROOT', 'ProcessBuilder("' + first + '") -> IOException');
                throw Java.use('java.io.IOException').$new('Cannot run program');
            }
            return this.start();
        };
        log('ROOT', 'ProcessBuilder.start hooked');
    } catch (e) { /* not needed */ }

    // ── Build.TAGS — hide test-keys ─────────────────────────────────────
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = 'release-keys';
        log('ROOT', 'Build.TAGS set to "release-keys"');
    } catch (e) { /* not needed */ }

    // ── System properties — hide root indicators ────────────────────────
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');
        var propOverrides = {
            'ro.build.tags': 'release-keys',
            'ro.debuggable': '0',
            'service.adb.root': '0',
            'ro.secure': '1'
        };
        SystemProperties.get.overload('java.lang.String').implementation = function (key) {
            if (propOverrides[key] !== undefined) return propOverrides[key];
            return this.get(key);
        };
        SystemProperties.get.overload('java.lang.String', 'java.lang.String').implementation = function (key, def) {
            if (propOverrides[key] !== undefined) return propOverrides[key];
            return this.get(key, def);
        };
        log('ROOT', 'SystemProperties.get hooked');
    } catch (e) { /* not needed */ }

    // ── Settings.Secure — hide developer options ────────────────────────
    try {
        var Secure = Java.use('android.provider.Settings$Secure');
        Secure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function (cr, name, def) {
            if (name === 'adb_enabled' || name === 'development_settings_enabled') return 0;
            return this.getInt(cr, name, def);
        };
        log('ROOT', 'Settings.Secure.getInt hooked');
    } catch (e) { /* not needed */ }

    // ── Native: fopen — hide root files at OS level ─────────────────────
    try {
        var fopen = Module.findExportByName('libc.so', 'fopen');
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function (args) {
                    this.block = false;
                    try {
                        var path = args[0].readUtf8String();
                        if (path && rootPathSet[path]) {
                            this.block = true;
                            this.path = path;
                        }
                    } catch (e) { /* can't read path, skip */ }
                },
                onLeave: function (retval) {
                    if (this.block) {
                        log('ROOT', 'fopen("' + this.path + '") -> NULL');
                        retval.replace(ptr(0));
                    }
                }
            });
            log('ROOT', 'Native fopen hooked');
        }
    } catch (e) {
        log('ERROR', 'fopen: ' + e);
    }

    // ── Native: access — hide root files ────────────────────────────────
    try {
        var access_func = Module.findExportByName('libc.so', 'access');
        if (access_func) {
            Interceptor.attach(access_func, {
                onEnter: function (args) {
                    this.block = false;
                    try {
                        var path = args[0].readUtf8String();
                        if (path && rootPathSet[path]) {
                            this.block = true;
                        }
                    } catch (e) { /* skip */ }
                },
                onLeave: function (retval) {
                    if (this.block) retval.replace(-1);
                }
            });
            log('ROOT', 'Native access() hooked');
        }
    } catch (e) { /* not critical */ }

    // ── Native: stat / lstat — hide root files ──────────────────────────
    try {
        ['stat', 'lstat', '__xstat', 'stat64'].forEach(function (fn) {
            var addr = Module.findExportByName('libc.so', fn);
            if (addr) {
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        this.block = false;
                        try {
                            var path = args[0].readUtf8String();
                            if (path && rootPathSet[path]) this.block = true;
                        } catch (e) { /* skip */ }
                    },
                    onLeave: function (retval) {
                        if (this.block) retval.replace(-1);
                    }
                });
            }
        });
        log('ROOT', 'Native stat/lstat hooked');
    } catch (e) { /* not critical */ }

    // ── RootBeer library ────────────────────────────────────────────────
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        ['isRooted', 'isRootedWithoutBusyBoxCheck', 'detectRootManagementApps',
         'detectPotentiallyDangerousApps', 'detectTestKeys', 'checkForBinary',
         'checkForDangerousProps', 'checkForRWPaths', 'detectRootCloakingApps',
         'checkSuExists', 'checkForRootNative', 'checkForMagiskBinary'].forEach(function (m) {
            try {
                RootBeer[m].overloads.forEach(function (o) { o.implementation = function () { return false; }; });
            } catch (e) { /* method not found */ }
        });
        log('ROOT', 'RootBeer library fully bypassed');
    } catch (e) { /* not present */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. RUNTIME TAMPERING / ANTI-FRIDA / ANTI-DEBUG BYPASS
// ═══════════════════════════════════════════════════════════════════════════════

function bypassTampering() {

    // ── Debug.isDebuggerConnected / waitingForDebugger ───────────────────
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () { return false; };
        Debug.waitingForDebugger.implementation = function () { return false; };
        log('TAMPER', 'Debug.isDebuggerConnected / waitingForDebugger -> false');
    } catch (e) { /* not needed */ }

    // ── Anti-Frida: /proc/self/maps scanning ────────────────────────────
    // Only filter lines from FileReader pointing to /proc/ paths
    try {
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
        var InputStreamReader = Java.use('java.io.InputStreamReader');

        // Track which BufferedReaders are wrapping /proc/ files
        var procReaders = new WeakSet ? new WeakSet() : null;

        // Hook FileReader to detect /proc/self/maps opens
        FileReader.$init.overload('java.lang.String').implementation = function (path) {
            this.$init(path);
            if (path && (path.indexOf('/proc/self/maps') !== -1 ||
                         path.indexOf('/proc/self/status') !== -1 ||
                         path.indexOf('/proc/self/task') !== -1)) {
                this._isProcFile = true;
            }
        };

        // Hook BufferedReader.readLine — only filter for proc file readers
        var originalReadLine = BufferedReader.readLine.overload();
        BufferedReader.readLine.overload().implementation = function () {
            var line = originalReadLine.call(this);

            // Check if this reader wraps a proc file
            // We check the underlying reader by inspecting the line content
            if (line !== null) {
                var lineStr = String(line);
                // Only filter lines that look like /proc/maps entries containing Frida
                if ((lineStr.indexOf('frida') !== -1 ||
                     lineStr.indexOf('gadget') !== -1 ||
                     lineStr.indexOf('gum-js-loop') !== -1 ||
                     lineStr.indexOf('linjector') !== -1) &&
                    (lineStr.indexOf('.so') !== -1 || lineStr.indexOf('deleted') !== -1 ||
                     lineStr.indexOf('/tmp/') !== -1 || lineStr.indexOf('r-xp') !== -1 ||
                     lineStr.indexOf('r--p') !== -1)) {
                    // This is a /proc/maps line mentioning Frida — skip it
                    log('TAMPER', 'Filtered Frida from /proc/maps line');
                    return originalReadLine.call(this);
                }
            }
            return line;
        };
        log('TAMPER', 'BufferedReader.readLine hooked (targeted /proc/maps filtering)');
    } catch (e) {
        log('ERROR', 'BufferedReader: ' + e);
    }

    // ── Anti-Frida: Port detection (27042, 27043) ───────────────────────
    try {
        var Socket = Java.use('java.net.Socket');
        var InetSocketAddress = Java.use('java.net.InetSocketAddress');

        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
            try {
                var sa = Java.cast(addr, InetSocketAddress);
                var port = sa.getPort();
                if (port === 27042 || port === 27043) {
                    log('TAMPER', 'Socket.connect to Frida port ' + port + ' -> blocked');
                    throw Java.use('java.net.ConnectException').$new('Connection refused');
                }
            } catch (castErr) {
                if (String(castErr).indexOf('ConnectException') !== -1) throw castErr;
                /* cast failed, let it through */
            }
            return this.connect(addr, timeout);
        };
        Socket.connect.overload('java.net.SocketAddress').implementation = function (addr) {
            try {
                var sa = Java.cast(addr, InetSocketAddress);
                var port = sa.getPort();
                if (port === 27042 || port === 27043) {
                    log('TAMPER', 'Socket.connect to Frida port ' + port + ' -> blocked');
                    throw Java.use('java.net.ConnectException').$new('Connection refused');
                }
            } catch (castErr) {
                if (String(castErr).indexOf('ConnectException') !== -1) throw castErr;
            }
            return this.connect(addr);
        };
        log('TAMPER', 'Socket.connect hooked (blocking Frida port 27042/27043)');
    } catch (e) {
        log('ERROR', 'Socket: ' + e);
    }

    // ── Anti-Frida: Native strstr — hide "frida" from string searches ───
    try {
        var strstr = Module.findExportByName('libc.so', 'strstr');
        if (strstr) {
            var fridaStrings = ['frida', 'LIBFRIDA', 'gadget', 'gum-js-loop', 'gmain', 'linjector'];
            Interceptor.attach(strstr, {
                onEnter: function (args) {
                    this.block = false;
                    try {
                        var needle = args[1].readUtf8String();
                        if (needle) {
                            for (var i = 0; i < fridaStrings.length; i++) {
                                if (needle.indexOf(fridaStrings[i]) !== -1) {
                                    this.block = true;
                                    break;
                                }
                            }
                        }
                    } catch (e) { /* can't read, skip */ }
                },
                onLeave: function (retval) {
                    if (this.block) retval.replace(ptr(0));
                }
            });
            log('TAMPER', 'Native strstr hooked (hiding Frida strings)');
        }
    } catch (e) { /* not critical */ }

    // ── Anti-ptrace ─────────────────────────────────────────────────────
    try {
        var ptrace = Module.findExportByName(null, 'ptrace');
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function (args) {
                    this.bypass = (args[0].toInt32() === 0); // PTRACE_TRACEME
                },
                onLeave: function (retval) {
                    if (this.bypass) {
                        log('TAMPER', 'ptrace(PTRACE_TRACEME) -> 0');
                        retval.replace(0);
                    }
                }
            });
            log('TAMPER', 'ptrace hooked (anti-debug bypass)');
        }
    } catch (e) { /* not critical */ }

    // ── System.exit — prevent app from killing itself ───────────────────
    try {
        var System = Java.use('java.lang.System');
        System.exit.implementation = function (code) {
            log('TAMPER', 'System.exit(' + code + ') -> blocked');
        };
        log('TAMPER', 'System.exit blocked');
    } catch (e) {
        log('ERROR', 'System.exit: ' + e);
    }

    // ── Process.killProcess — prevent self-kill ─────────────────────────
    try {
        var Process = Java.use('android.os.Process');
        Process.killProcess.implementation = function (pid) {
            if (pid === Process.myPid()) {
                log('TAMPER', 'Process.killProcess(self) -> blocked');
                return;
            }
            Process.killProcess(pid);
        };
        log('TAMPER', 'Process.killProcess hooked');
    } catch (e) { /* not needed */ }

    // ── Emulator detection bypass ───────────────────────────────────────
    try {
        var Build = Java.use('android.os.Build');
        var emuIndicators = ['generic', 'emulator', 'sdk', 'goldfish', 'ranchu', 'vbox', 'genymotion'];
        var spoofValues = {
            'FINGERPRINT': 'google/walleye/walleye:8.1.0/OPM1.171019.021/4565141:user/release-keys',
            'MODEL': 'Pixel 2', 'MANUFACTURER': 'Google', 'BRAND': 'google',
            'DEVICE': 'walleye', 'PRODUCT': 'walleye', 'HARDWARE': 'walleye', 'BOARD': 'walleye',
        };
        for (var field in spoofValues) {
            try {
                var current = String(Build[field].value).toLowerCase();
                var isEmu = false;
                for (var j = 0; j < emuIndicators.length; j++) {
                    if (current.indexOf(emuIndicators[j]) !== -1) { isEmu = true; break; }
                }
                if (isEmu) {
                    Build[field].value = spoofValues[field];
                    log('TAMPER', 'Build.' + field + ' spoofed');
                }
            } catch (e) { /* field not writable */ }
        }
    } catch (e) { /* not critical */ }

    // ── Xposed detection bypass (StackTrace) ────────────────────────────
    try {
        var Thread = Java.use('java.lang.Thread');
        Thread.getStackTrace.implementation = function () {
            var stack = this.getStackTrace();
            var filtered = [];
            for (var i = 0; i < stack.length; i++) {
                var cn = String(stack[i].getClassName());
                if (cn.indexOf('de.robv.android.xposed') === -1 &&
                    cn.indexOf('com.saurik.substrate') === -1) {
                    filtered.push(stack[i]);
                }
            }
            return filtered;
        };
        log('TAMPER', 'Thread.getStackTrace Xposed/Substrate filtered');
    } catch (e) { /* not needed */ }

    // ── Native open() — track /proc/self/status for TracerPid ───────────
    try {
        var openFunc = Module.findExportByName('libc.so', 'open');
        if (openFunc) {
            var trackedFds = {};
            Interceptor.attach(openFunc, {
                onEnter: function (args) {
                    try {
                        this.path = args[0].readUtf8String();
                    } catch (e) { this.path = null; }
                },
                onLeave: function (retval) {
                    if (this.path && this.path.indexOf('/proc/self/status') !== -1) {
                        trackedFds[retval.toInt32()] = true;
                    }
                }
            });

            // Hook read() to modify TracerPid in /proc/self/status
            var readFunc = Module.findExportByName('libc.so', 'read');
            if (readFunc) {
                Interceptor.attach(readFunc, {
                    onEnter: function (args) {
                        this.fd = args[0].toInt32();
                        this.buf = args[1];
                        this.isTracked = trackedFds[this.fd] || false;
                    },
                    onLeave: function (retval) {
                        if (this.isTracked && retval.toInt32() > 0) {
                            try {
                                var content = this.buf.readUtf8String(retval.toInt32());
                                if (content.indexOf('TracerPid') !== -1) {
                                    var patched = content.replace(/TracerPid:\s*\d+/, 'TracerPid:\t0');
                                    this.buf.writeUtf8String(patched);
                                    log('TAMPER', 'TracerPid set to 0 in /proc/self/status');
                                }
                            } catch (e) { /* can't patch, not critical */ }
                        }
                    }
                });
            }
            log('TAMPER', 'Native open/read hooked (TracerPid spoofing)');
        }
    } catch (e) { /* not critical */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ENTRY POINT
// ═══════════════════════════════════════════════════════════════════════════════

console.log('');
console.log(Color.CYAN + Color.BOLD + '  ╔══════════════════════════════════════════════════╗' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ║       Universal Bypass — APK Analyzer            ║' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ║   SSL Pinning + Root + Runtime Tampering          ║' + Color.RESET);
console.log(Color.CYAN + Color.BOLD + '  ╚══════════════════════════════════════════════════╝' + Color.RESET);
console.log('');

Java.perform(function () {
    log('SSL',    '═══ SSL Pinning Bypass ═══');
    bypassSSL();
    console.log('');

    log('ROOT',   '═══ Root Detection Bypass ═══');
    bypassRoot();
    console.log('');

    log('TAMPER', '═══ Runtime Tampering Bypass ═══');
    bypassTampering();
    console.log('');

    console.log(Color.GREEN + Color.BOLD + '  [+] All bypasses loaded. App should be unprotected.' + Color.RESET);
    console.log(Color.DIM + '  github.com/worldtreeboy/apkAnalyzer' + Color.RESET);
    console.log('');
});
