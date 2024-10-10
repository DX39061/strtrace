#!/usr/bin/env python3
import frida
import sys
import os

def on_message(message, _):    
    if message['type'] == 'send':
        if message['payload']['type'] == 'finish':
            global session
            session.detach()
            sys.stderr.write("finished tracing\n")
            sys.stderr.write("Press Enter to exit...\n")
    else:
        print(message)

def parse_args():
    app_name = None
    module_name = None
    function_offset = None
    spawn = False
    if "--app" not in sys.argv or "--func" not in sys.argv:
        sys.stderr.write("Usage: %s --app <app_name> --func <module_name>!<function_offset> [--spawn]" % sys.argv[0])
        sys.exit(1)
    else:
        sys.stderr.write(" ".join(sys.argv) + "\n")
    for i in range(1, len(sys.argv)):
        if sys.argv[i] == "--app":
            app_name = sys.argv[i+1]
        elif sys.argv[i] == "--func":
            module_name, function_offset = sys.argv[i+1].split("!")
        elif sys.argv[i] == "--spawn":
            spawn = True
    return app_name, module_name, eval(function_offset), spawn

def main(app_name, module_name, function_offset, spawn):
    global session
    args = {"module_name": module_name, "function_offset": function_offset}
    device = frida.get_usb_device()
    if spawn:
        pid = device.spawn([app_name])
        session = device.attach(pid)
    else:
        target_process = device.get_process(app_name)
        session = device.attach(target_process.pid)
    js_file = os.path.abspath(__file__).replace("strtrace.py", "strtrace.js")    
    script = session.create_script(open(js_file).read())
    script.on('message', on_message)
    script.load()
    script.post({"type": "args", "data": args})
    sys.stderr.write("script loaded, waiting function...\n")
    if spawn:
        device.resume(pid)
    input()
    session.detach()

if __name__ == "__main__":
    try:
        app, module, func_offset, spawn = parse_args()
        main(app, module, func_offset, spawn)
    except frida.ProcessNotFoundError:
        sys.stderr.write("Process %s not found" % app)
    except KeyboardInterrupt:
        sys.stderr.write("Exiting...")

