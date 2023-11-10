import frida
import sys

packageName = 'com.ms.afdshijia.mi'
scriptFile = "hookLite.js"
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[*] {0}".format(message['description']))
    else:
        pass
        print(message)

def getSession(startOption, target):
    device = frida.get_usb_device()
    session = -1
    try:
        if startOption == 'attach':
            session = device.attach(target)
            return session
        elif startOption == 'spawn':
            if type(target) != str:
                print('param error: spawn need target is target process name')
                return session

            pid = device.spawn(target)
            session = device.attach(pid)
            device.resume(pid)
    except frida.NotSupportedError:
        print('process not found')
    except frida.ProcessNotFoundError:
        print('ProcessNotFoundError')
    except frida.ProcessNotRespondingError:
        print('ProcessNotRespondingError')
    except frida.ServerNotRunningError:
        print('frida server is not running.')


    if type(session) == int and session == -1:
        print('error: session get failed')
        exit(0)

    return session


session = getSession('attach', 16104)
# a = device.attach(31999)
# pid = device.spawn(packageName)
# session = device.attach(pid)
# device.resume(pid)

#读取文件javascript
with open(scriptFile, encoding='UTF-8') as file:
    script = session.create_script(file.read())

script.on("message", on_message)
script.load()

#挂起进程
sys.stdin.read()

