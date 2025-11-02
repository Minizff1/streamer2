from flask import Flask, request, redirect, url_for, session, jsonify, send_file
import hashlib
import sys
import psutil
from keyauth import api
import winreg
from Memory import *

app = Flask(__name__)
app.secret_key = '703822238'

def getchecksum():
    md5_hash = hashlib.md5()
    with open(''.join(sys.argv), "rb") as file:
        md5_hash.update(file.read())
    return md5_hash.hexdigest()

keyauthapp = api(
    name="22ffwhite44's Application",
    ownerid="b56K7A5whK",
    secret="0ff80b19edccb863cc82bdca8c7f252d732124d87bd4e75968ea784f96aef832",
    version="1.0",
    hash_to_check=getchecksum()
)

if sys.platform == "win32":
  ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        try:
            keyauthapp.login(username, password)
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        except Exception as e:
            return f"<h3>Login failed: {str(e)}</h3><a href='/'>Back to login</a>"

    from flask import render_template
    return render_template('login.html')

def add_to_startup():
    file_path = sys.executable  # Path to .exe once converted with PyInstaller
    reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "MirrorShopApp", 0, winreg.REG_SZ, file_path)
    except Exception as e:
        print(f"Startup registration failed: {e}")


@app.route('/index.html')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    from flask import render_template
    return render_template('index.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/execute', methods=['POST'])
def execute_command():
    data = request.get_json()
    command = data.get('command')

    if not command:
        return jsonify({"message": "No command received."}), 400

    response_message = process_command(command)
    return jsonify({"message": response_message})


@app.route('/status')
def check_status():
    process_name = "HD-Player.exe"
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == process_name:
            return jsonify({"status": "online"})
    return jsonify({"status": "offline"})


def process_command(command):
    match command:
        case "aimbotscan":
            HEADLOAD()
            return "Aimbot loaded successfully."
        case "aimbotenable":
            HEADON()
            return "Aim : Neck Enabled"
        case "aimbotdisable":
            HEADOFF()
            return "Aim : Neck Disabled"
        case "leftShoulderOn":
            LEFTSHOULDERON()
            return "Aim : Left-shoulder Enabled"
        case "leftShoulderOff":
            LEFTSHOULDEROFF()
            return "Aim : Left-shoulder Disabled"
        case "rightShoulderOn":
            RIGHTSHOULDERON()
            return "Aim : Right-shoulder Enabled"
        case "rightShoulderOff":
            RIGHTSHOULDEROFF()
            return "Aim : Right-shoulder Disabled"
        # Internal tab hacks (OOP)
        case "load_aimbot":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().load_aimbot()
        case "head_aim_on":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().head_aim_on()
        case "head_aim_off":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().head_aim_off()
        case "right_shoulder_aim_on":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().right_shoulder_aim_on()
        case "left_shoulder_aim_on":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().left_shoulder_aim_on()
        case "shoulder_aim_off":
            from Memory import get_aimbot_internal
            return get_aimbot_internal().shoulder_aim_off()
        case "loadsniper":
            SNIPERSCOPELOAD()
            SNIPERSWITCHLOAD()
            return "Sniper architect Enabled"
        case "sniperscopeenable":
            ACTIVATELOADEDSCOPE()
            return "Sniper auto aim Set to enemy"
        case "sniperscopedisable":
            REMOVELOADEDSCOPE()
            return "Sniper auto aim Set to normal"
        case "sniperswitchenable":
            ACTIVATELOADEDSWITCH()
            return "Sniper fast switch enabled"
        case "sniperswitchdisable":
            REMOVELOADEDSWITCH()
            return "Sniper fast switch disabled"
        # Other hacks
        case "box3d":
            box3d()
            return "Box 3D Chams Enabled"
        case "chamsmenu":
            chamsmenu()
            return "Chams Menu Enabled"
        case "chams3d":
            chams3d()
            return "3D Chams Enabled"
        case "removerecoil":
            RemoveRecoil()
            return "No Recoil Enabled"
        case "addrecoil":
            AddRecoil()
            return "No Recoil Removed"
        case "wallhackload":
            WALLHACKLOAD()
            return "Wallhack pattern loaded."
        case "wallhackenable":
            ACTIVATEWALLHACK()
            return "Wallhack enabled."
        case "wallhackdisable":
            REMOVEWALLHACK()
            return "Wallhack disabled."
        case "speedhackload":
            SPEEDHACKLOAD()
            return "Speed hack pattern loaded."
        case "speedhackenable":
            ACTIVATELOADEDSPEED()
            return "Speed hack enabled."
        case "speedhackdisable":
            REMOVESPEEDHACK()
            return "Speed hack disabled."
        case _:
            return f"Unknown command: {command}"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
