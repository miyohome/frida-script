/* frida script core function */

/**
 * findClass - 在当前Java虚拟机中查找指定类名称的类。
 *
 * @param {string} className - 要查找的类的名称。
 * @returns {Class|null} - 如果找到类，则返回该类的引用，否则返回null。
 *
 * @example
 * // 使用示例：
 * const className = 'com.example.MyClass';
 * const foundClass = findClass(className);
 * if (foundClass !== null) {
 *     // 对找到的类进行操作
 * } else {
 *     console.log(`无法找到类 ${className}`);
 * }
 *
 * @description
 * 该函数尝试通过使用 Java.use 和 Java.enumerateClassLoadersSync 来查找指定的类。
 * 如果成功找到类，它将返回类的引用。如果未找到类，它将返回null。
 * 注意：该函数可能会更改当前类加载器以确保正确查找类。
 *
 * @created 2023-07-13
 * @last-modified 2023-09-05 10:42
 * @author mahiro
 * @version 1.0.0
 */
function findClass(className)
{
    let clazz = null;
    try {
        clazz = Java.use(className);
    } catch (ignore) {
    }

    if (clazz == null) {
        let classLoaders = Java.enumerateClassLoadersSync();
        if (classLoaders != null) {
            classLoaders.forEach(classLoader => {
                try {
                    if (clazz == null) {
                        // try findClass
                        clazz = classLoader.findClass(className)
                        // replace classloader
                        Java.classFactory.loader = classLoader;
                    }
                }
                catch(ignore) {
                }
            });
        }
    }
    return clazz;
}


/**
 * Android类引用对象
 *
 * @namespace
 * @property {JavaClass} android_os_Process - 对android.os.Process类的引用。
 * @property {JavaClass} java_lang_Thread - 对java.lang.Thread类的引用。
 *
 * @example
 * // 使用示例：
 * const processClass = and.android_os_Process;
 * const threadClass = and.java_lang_Thread;
 *
 * // 获取进程 PID
 * and.android_os_Process.myPid()
 * // 获取进程 UID
 * and.android_os_Process.myUid()
 *
 * @description
 * 该对象包含了对Android中特定类的引用，用于在Java虚拟机中操作和监视这些类。
 * 可以使用这些引用来执行各种与类相关的操作，如方法拦截和字段访问。
 *
 * @created 2023-09-05
 * @last-modified 2023-09-05
 * @author mahiro
 * @version 1.0.0
 */
let and = {
    android_app_ActivityThread : findClass("android.app.ActivityThread"),
    android_os_Process : findClass("android.os.Process"),
    android_util_Log : findClass("android.util.Log"),
    android_view_View : findClass("android.view.View"),
    android_view_ViewGroup : findClass("android.view.ViewGroup"),

    java_lang_reflect_Modifier : findClass("java.lang.reflect.Modifier"),

    java_lang_Thread : findClass("java.lang.Thread"),
    java_util_IdentityHashMap : findClass("java.util.IdentityHashMap"),
}
let classes = {
    common : {
        Runtime : findClass("java.lang.Runtime")
    },

    server : {
        wm: {
            // RootWindowContainer: findClass("com.android.server.wm.RootWindowContainer"),
        },
    }
};


/**
 * ColorLibrary - 颜色库
 *
 *
 * @description
 * 用于修改输出文本的字体颜色和背景色。
 *
 * @created 2023-09-05
 * @last-modified 2023-09-05
 * @author mahiro
 * @version 1.0.0
 */
const ColorLibrary = {
    // 字体前景颜色表
    FontcolorMap: {
        black: '\u001b[30m',
        red: '\u001b[31m',
        green: '\u001b[32m',
        yellow: '\u001b[33m',
        blue: '\u001b[34m',
        magenta: '\u001b[35m',
        cyan: '\u001b[36m',
        white: '\u001b[37m',
        brightBlack: '\u001b[90m',
        brightRed: '\u001b[91m',
        brightGreen: '\u001b[92m',
        brightYellow: '\u001b[93m',
        brightBlue: '\u001b[94m',
        brightMagenta: '\u001b[95m',
        brightCyan: '\u001b[96m',
        brightWhite: '\u001b[97m',
    },

    // 字体背景颜色表
    BgcolorMap: {
        bgBlack: '\u001b[40m',
        bgRed: '\u001b[41m',
        bgGreen: '\u001b[42m',
        bgYellow: '\u001b[43m',
        bgBlue: '\u001b[44m',
        bgMagenta: '\u001b[45m',
        bgCyan: '\u001b[46m',
        bgWhite: '\u001b[47m',
        bgBrightBlack: '\u001b[100m',
        bgBrightRed: '\u001b[101m',
        bgBrightGreen: '\u001b[102m',
        bgBrightYellow: '\u001b[103m',
        bgBrightBlue: '\u001b[104m',
        bgBrightMagenta: '\u001b[105m',
        bgBrightCyan: '\u001b[106m',
        bgBrightWhite: '\u001b[107m'
    },

    /**
     * 修改文本颜色和背景色并返回新的文本。
     *
     * @param {string} text - 要修改颜色的文本。
     * @param {string} color - 字体颜色。默认为 'white'。
     * @param {string} backgroundColor - 背景颜色。默认为 'bgBlack'。
     * @returns {string} - 修改后的文本。
     *
     *
     * @example
     * ColorLibrary.coloredText("我是黑背景白字体");
     * ColorLibrary.coloredText("我是黑绿背景红字体", 'red', 'bgGreen');
     *
     * @description
     * 该对象包含了对Android中特定类的引用，用于在Java虚拟机中操作和监视这些类。
     * 可以使用这些引用来执行各种与类相关的操作，如方法拦截和字段访问。
     *
     * @created 2023-09-05
     * @last-modified 2023-09-05
     * @author mahiro
     * @version 1.0.0
     */
    coloredText: function(text, color = 'white', backgroundColor = 'bgBlack') {
        const resetCode = '\u001b[0m';
        const colorCode = this.FontcolorMap[color] || '';
        const bgColorCode = this.BgcolorMap[backgroundColor] || '';
        return `${bgColorCode}${colorCode}${text}${resetCode}`;
    },
};


/*
   基础功能
* */
function log(text, TAG="")
{
    // send("[*]" + text);
    console.log("[*] " + text);
    Java.perform(() => and.android_util_Log.i(TAG, `${text}`))
}


function getStackTrace() {
    const currentThread = Java.use('java.lang.Thread').currentThread();
    const stackTrace = currentThread.getStackTrace();
    let stackTraceString = '';

    for (let i = 2; i < stackTrace.length; i++) {
        stackTraceString += '\t' + stackTrace[i].toString() + '\n';
    }

    log(ColorLibrary.coloredText('Backtrace: \n' + stackTraceString, 'brightWight'));
    return stackTraceString;
}


function hashcode(string) {
    //set variable hash as 0
    var hash = 0;
    // if the length of the string is 0, return 0
    if (string.length === 0) return hash;
    for (let i = 0; i < string.length; i++) {
        let ch = string.charCodeAt(i);
        hash = ((hash << 5) - hash) + ch;
        hash = hash & hash;
    }
    return hash;
}


//////////////////////////////////////////////////////////////////////////////
// 2.0 hook 方式

function sharpHookCommon(className, methodName, overload, beforeCallback, afterCallback) {
    // 获取返回值类型
    const returnType = overload.returnType.className;
    // 获取参数类型
    const argumentTypes = overload.argumentTypes.map(argType => argType.className);
    // 获取参数类型列表
    const argumentTypesList = argumentTypes.join(', ');
    // 获取 pid uid
    const uid = and.android_os_Process.myUid();
    const pid = and.android_os_Process.myPid();

    // 保存彩色日志 返回类型与类名称和函数名称
    // example:[int android.os.Process.myPid]
    let textBody = `${ColorLibrary.coloredText(returnType, 'yellow')} ${ColorLibrary.coloredText(className, 'green')}.${ColorLibrary.coloredText(methodName, 'brightGreen')}`;

    // 保存完整日志信息
    log(ColorLibrary.coloredText('Hooking ', 'brightWight') + textBody
        + '(' + ColorLibrary.coloredText(argumentTypesList, 'brightRed') + ')');

    // 记录重入属性
    let reenter = false;

    // 计算hash值
    let hash = hashcode(textBody)

    // 替换目标方法的实现
    overload.implementation = function() {
        // 获取回调参数
        let params = {
            reenter : reenter,
            className : className,
            methodName : methodName,

            thisObject : this,
            args : arguments,

            call : true,
            stack : false
        };



        // 获取参数值列表
        const args = [...arguments];
        const argumentValueList = args.map(arg => arg == null ? "null" : arg.toString()).join(', ');

        // 准备函数签名、参数列表
        let info = `${getCurrentTime()} ${uid} ${pid} ${and.java_lang_Thread.currentThread().getId()} ${textBody}(${ColorLibrary.coloredText(argumentValueList, 'brightRed')})`;
        // + '(' + ColorLibrary.coloredText(argumentValueList, 'brightRed') + ') = ';
        log(`${info} | before called`);

        // 在调用前执行前回调函数
        if (typeof beforeCallback === 'function' && reenter === false) {
            // 防止重入
            reenter = true;
            beforeCallback(params);
        }

        if (params.stack === true) {
            getStackTrace();
        }

        if (params.call === true) {
            // 调用原始方法
            var result = overload.apply(this, arguments);

            // [-] 消除重入标志
            if (reenter === true) {
                reenter = false;
            }

            // 在调用后执行后回调函数
            if (typeof afterCallback === 'function') {
                params.retval = result;
                afterCallback(params);
                result = params.retval;
            }

            // 打印函数签名、参数列表、返回值
            info += ' = ' + ColorLibrary.coloredText(result, 'brightBlue')
        }
        else {
            info += ' refuse'
        }

        // 输出调用后的日志
        log(`${info} | after called `);

        // 拒绝调用时 返回值做处理
        if (params.call === false) {
            // log("default return value.")
            // 返回默认值
            if (returnType === 'void') {
                return;
            } else if (returnType === 'boolean') {
                return false; // 默认返回 false
            } else if (returnType === 'int') {
                return 0; // 默认返回 0
            } else {
                return null; // 默认返回 null
            }
        }
        return result;
    };
}


// 枚举参数，表示hook的类别
var HookCategory = {
    ALL_MEMBERS: 0,
    SINGLE_FUNCTION: 1,
    CONSTRUCTOR: 2
};


function fastHook(type, name, beforeCallback= null, afterCallback= null) {
    let clazz = null;
    if (type === HookCategory.CONSTRUCTOR) {
        clazz = findClass(name);
        if (clazz == null || clazz == undefined) {
            console.log(`can't find className ${name} return ${clazz}`);
        } else {
            try {
                clazz.$init.overloads.forEach(function (overload) {
                    sharpHookCommon(name, '$init', overload, beforeCallback, afterCallback);
                });
            } catch (e) {
                console.log(e)
            }
        }
        return;
    }
    if (type === HookCategory.ALL_MEMBERS) {
        clazz = findClass(name);
        if (clazz == null) {
            console.log(`can't find className ${name} return ${clazz}`);
        } else {
            clazz.class.getDeclaredMethods().forEach(function (targetMethod) {
                let methodName = targetMethod.getName()
                if (clazz[methodName] === undefined || clazz[methodName] == null) {
                    console.log(`can't find methodName ${methodName} return ${clazz[methodName]}`);
                } else {
                    clazz[methodName].overloads.forEach(overload => {
                        sharpHookCommon(name, methodName, overload, beforeCallback, afterCallback);
                    });
                }
            });
        }
        return;
    }
    if (type === HookCategory.SINGLE_FUNCTION) {
        // 获取类路径
        let findClassByString = function(text) {
            return text.substring(0, text.lastIndexOf('.'))
        }
        // 获取函数名称
        let findMethodByString = function(text) {
            return text.substring(text.lastIndexOf('.') + 1)
        }
        // 获取类路径
        const className = findClassByString(name);
        // 获取函数名称
        const methodName = findMethodByString(name);
        
        // 获取 java 类
        clazz = findClass(className);
        if (clazz == null) {
            console.log(`can't find className ${className} return ${clazz}`);
            return;
        }

        if (clazz[methodName] === undefined || clazz[methodName] == null) {
            console.log(`can't find methodName ${methodName} return ${clazz[methodName]}`);
            return;
        }

        clazz[methodName].overloads.forEach(overload => {
            sharpHookCommon(className, methodName, overload, beforeCallback, afterCallback);
        });
    }
}


function hookClass(name, beforeCallback= null, afterCallback= null) {
    fastHook(HookCategory.ALL_MEMBERS, name, beforeCallback, afterCallback);
}


function hookConstruction(name, beforeCallback= null, afterCallback= null) {
    fastHook(HookCategory.CONSTRUCTOR, name, beforeCallback, afterCallback);
}


function hookMethod(name, beforeCallback= null, afterCallback= null) {
    fastHook(HookCategory.SINGLE_FUNCTION, name, beforeCallback, afterCallback);
}


function resolveIntent(intent)
{
    try {

        if (intent != null) {
            log("=============    resolveIntent start    =============")
            try
            {
                intent = Java.cast(intent, findClass("android.content.Intent"));
                log(JSON.stringify(intent))

                log("intent.getType() = " + intent.getType());
                log("intent.getAction() = " + intent.getAction());
                log("intent.getPackage() = " + intent.getPackage());
                log("intent.getComponent() =  " + intent.getComponent());
                log("intent.getData() =  " + intent.getData());
                log("intent.getFlags() =  " + intent.getFlags());
                log("intent.getClipData() =  " + intent.getClipData());
                if (intent.getData()) {
                    log("intent.getScheme() =  " + intent.getScheme());
                }

                let bundle = intent.getExtras();
                if (bundle != null) {
                    bundle.keySet().toArray().forEach(function(key){
                        log("string key:  " + key + "  value:  " + bundle.get(key));
                    });
                }
            } catch (e){
                log(e);
            }
            log("=============    resolveIntent  end     =============")
        } else {
            console.log("intent is null");
        }
    } catch (e) {

    }
}


function resolveBundle(bundle)
{
    log("=============    resolveBundle start    =============")
    try
    {
        bundle.keySet().toArray().forEach(function(key){
            log("string key:  " + key + "  value:  " + bundle.get(key));
        });
    } catch (e){

    }
    log("=============    resolveBundle  end     =============")
}


function baseTrace() {
    hookClass("android.app.IActivityManager$Stub$Proxy");
    hookClass("android.app.IActivityTaskManager$Stub$Proxy");
    hookClass("android.app.IActivityClientController$Stub$Proxy");
    hookClass("android.content.pm.IPackageManager$Stub$Proxy");
    hookClass("android.view.IWindowSession$Stub$Proxy");
    hookClass("android.net.IConnectivityManager$Stub$Proxy");
    hookClass("com.android.internal.telephony.ITelephony$Stub$Proxy");
    hookClass("android.accounts.IAccountManager$Stub$Proxy");
    // hookClass("android.content.ContentProvider");
    hookClass("android.app.admin.IDevicePolicyManager$Stub$Proxy");
    hookClass("android.app.INotificationManager$Stub$Proxy");
    hookClass("android.app.job.IJobScheduler$Stub$Proxy");
    hookClass("android.media.IAudioService$Stub$Proxy");
    hookClass("com.android.internal.telephony.ISub$Stub$Proxy");
    hookClass("android.content.ContentProviderProxy");
    hookClass("android.content.ContentProvider$Transport");
    hookClass("com.android.internal.view.IInputMethodManager$Stub$Proxy");
    hookClass("android.view.accessibility.IAccessibilityManager$Stub$Proxy");
    // hookClass("android.content.ContentResolver");
    hookClass("android.os.storage.IStorageManager$Stub$Proxy");
    hookClass("com.android.providers.media.MediaProvider");
    // hookClass("com.google.android.apps.photos.localmedia.ui.LocalPhotosActivity");
    hookClass("android.hardware.display.IDisplayManager$Stub$Proxy");
    // hookClass("android.app.Instrumentation")
    hookClass("com.android.server.content.SyncManager");
    hookClass("android.os.IUserManager$Stub$Proxy");
    hookClass("android.content.IContentService$Stub$Proxy");
    // hookClass"android.app.ActivityThread");
    // hookClass"android.app.Activity");


    // hookClass"android.net.Uri");
    // hookConstruction("android.net.Uri");
    // hookClass"java.net.URL");
    // hookConstruction("java.net.URL");

    // hookMethod("android.app.SharedPreferencesImpl.getBoolean");
    // hookMethod("android.app.SharedPreferencesImpl.getInt");
    hookMethod("android.app.SharedPreferencesImpl.getLong");
    hookMethod("android.app.SharedPreferencesImpl.getFloat");
    hookMethod("android.app.SharedPreferencesImpl.getString");
    hookMethod("android.app.SharedPreferencesImpl.getStringSet");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putBoolean");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putInt");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putLong");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putFloat");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putString");
    hookMethod("android.app.SharedPreferencesImpl$EditorImpl.putStringSet");
}


function getCurrentTime() {
    const now = new Date();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const milliseconds = String(now.getMilliseconds()).padStart(3, '0');

    return `${month}-${day} ${hours}:${minutes}:${seconds}.${milliseconds}`;
}


function catObject(obj, type, callback=null) {
    try {
        if (obj == null) {
            log("Unable cat object null");
            return;
        }

        let clazz;
        if (type == null) {
            clazz = obj.getClass();
        } else {
            clazz = findClass(type).class;
        }


        log(``);
        log(`============ ${clazz.getName()} ============ `);
        clazz.getDeclaredFields().forEach(field => {
            field.setAccessible(true);

            let fieldClass = field.getClass();
            let fieldName = field.getName();
            let fieldObject = field.get(obj);

            let modifiers = field.getModifiers();
            let isFinal = and.java_lang_reflect_Modifier.isFinal(modifiers);
            let isStatic = and.java_lang_reflect_Modifier.isStatic(modifiers);

            // if (isFinal && isStatic) {
            //
            // }
            // else
            {
                if (callback == null) {
                    log(`${fieldName} = ${fieldObject} ${JSON.stringify(fieldObject)}`);
                } else {
                    callback(fieldClass, fieldName, fieldObject);
                }
            }

        });
        log(`============ ${clazz.getName()} ============ `);
        log(``);
    } catch (e) {
        log(e);
    }
}


function catMap(obj) {
    console.log("=== catMap === for " + obj);
    if (obj != null) {
        let map = Java.cast(obj, Java.use("java.util.HashMap"));

        console.log("HashMap size:" + map.size());
        let iterator = map.entrySet().iterator();
        while (iterator.hasNext()) {
            let entry = iterator.next();
            console.log(entry.toString());
        }
    }
}


function enumerateModules(callback) {
    console.log("========== B enumerateModules B ==========")
    Java.perform(() => {
        Process.enumerateModules().forEach(module => {
            let params = {
                name : module.name,
                base : module.base,
                size : module.size,
                path : module.path,
                imports : module.enumerateImports()
            }
            callback(params);
        })
    })
    console.log("========== E enumerateModules E ==========")
}


Java.perform(function () {
    console.log("uid: " + and.android_os_Process.myUid());
    console.log("pid: " + and.android_os_Process.myPid());

    // do something
});
