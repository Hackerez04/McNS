import requests
import pyfiglet
import random
import threading
import os
import time
import datetime
import json
import re

account_progression_multi = []
account_progression_multi2 = []
account_progression_nn = []
account_success = []


def create_log(typ, msg, other):
    current_time = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    f = open("mcns-logs.txt", "a")
    if other == "":
        other = "none"
    text = "[%s] - %s\n%s\n[%s]\n----------\n" % (typ, current_time, str(msg), str(other))
    f.write(text)
    f.close()


def get_data(check_emails, v):
    global account_progression_multi, account_progression_nn, account_progression_multi2

    f = open("accounts.json")
    data = json.load(f)
    for acc in data["account"]:
        if acc["email"] in check_emails:
            if v == 1:
                account_progression_multi.append([acc["token"], acc["email"], acc["password"], 0,
                                                  [name["name"] for name in acc["name-list"]], "not-changed"])  # i love this
            elif v == 2:
                account_progression_nn.append([acc["token"], acc["email"], acc["password"], 0,
                                               [name["name"] for name in acc["name-list"]], "not-changed"])
            elif v == 3:
                account_progression_multi2.append([acc["token"], acc["email"], acc["password"], 0,
                                                  [name["name"] for name in acc["name-list"]], "not-changed"])
    if v == 1:
        print("[+] Loaded %s Account for Func. 1" % (len(account_progression_multi)))
    elif v == 2:
        print("[+] Loaded %s Account for Func. 2" % (len(account_progression_nn)))
    elif v == 3:
        print("[+] Loaded %s Account for Func. 3" % (len(account_progression_nn)))


def token_login(token, name):
    url = "https://api.minecraftservices.com/minecraft/profile"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            account_info = response.json()
            print("[+] Logged in!")
            print("[+] Account Information:")
            print("- Username:", account_info.get("name"))
            print("- UUID:", account_info.get("id"))
            # print("[*] Trying to change the name...")
            url = f"https://api.minecraftservices.com/minecraft/profile/name/{name}"
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.put(url, headers=headers)
            # print(response.json())

            if "ACTIVE" in str(response.json()):
                print("[+] Name changed!!! :D (%s)" % (name))
                # create_log("INFO", "Name changed!\n%s" % (str(response.json())))
                create_log("INFO", "Name changed!\n%s" % (response.json()), "")
                return "CHANGED"
            else:
                print("[-] Name not changed.")
                print(response.json())
                # create_log("INFO", "Name not changed.\n%s" % (str(response.json())))
                return "NOT-CHANGED"

        else:
            if response.status_code == 401 or response.status_code == 404:
                print("Need Microsoft authentication")
                return "CHANGE-AUTH-METHOD"
            else:
                print("[-] Failed to retrieve account information with status code:", response.status_code)
                print(response.text)
                return "ERROR"

    except OSError as oErr:
        print("PROXY ERROR")
        # create_log("PROXY-ERROR", "Tunnel connection failed: 407 Proxy Authentication Required")
        create_log("WARNING", "Proxy Error", "%s" % (oErr))
        return "PROXY-ERROR"

    except Exception as error:
        print("[-] Something went wrong!")
        print("%s" % (error))
        create_log("ERROR", "Something went wrong!\n%s" % (error), "")
        return "ERROR"


def microsoft_login(ac_email, ac_password, name):
    error_index = 0
    try:
        url = "https://api.minecraftservices.com/minecraft/profile"
        session = requests.Session()
        res = session.get(
            "https://login.live.com/oauth20_authorize.srf?client_id=000000004C12AE6F&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en")
        res_str = res.content.decode()
        sfttag = re.search("""(?<=sFTTag:'<input type="hidden" name="PPFT" id="i0327" value=")(.*)(?="\/>')""",
                           res_str).group()
        urlpost = re.search("""(?<=urlPost:')(.*)(?=',au)""", res_str).group()
        # hystory of urlpost: av, aw, au
        # print(sfttag)
        # print(urlpost)
        data = {
            "login": "%s" % (ac_email),
            "loginfmt": "%s" % (ac_email),
            "passwd": "%s" % (ac_password),
            "PPFT": "%s" % sfttag
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        res = session.post(urlpost, data=data, headers=headers, allow_redirects=True)
        try:
            raw_login_data = res.url.split("#")[1]  # split the url to get the parameters
        except IndexError:
            error_index = 1
        if error_index != 1:
            login_data = dict(
                item.split("=") for item in raw_login_data.split("&"))  # create a dictionary of the parameters
            login_data["access_token"] = requests.utils.unquote(
                login_data["access_token"])  # URL decode the access token
            login_data["refresh_token"] = requests.utils.unquote(
                login_data["refresh_token"])  # URL decode the refresh token
            # print(login_data)  # print the data
            access_token = login_data["access_token"]
            refresh_token = login_data["refresh_token"]
            session.cookies.clear()
            # step 2
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            data = {
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": "%s" % (access_token)
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT"
            }

            res = session.post("https://user.auth.xboxlive.com/user/authenticate", headers=headers, json=data)
            res = res.json()
            # print(res)
            xbox_token = res["Token"]
            uhs = res["DisplayClaims"]["xui"][0]["uhs"]
            # step 3
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            data = {
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [
                        "%s" % (xbox_token)
                    ]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            }

            res = session.post("https://xsts.auth.xboxlive.com/xsts/authorize", headers=headers, json=data)
            res = res.json()
            # print(res)
            xsts_token = res["Token"]
            # step 4
            headers = {
                "Content-Type": "application/json"
            }
            data = {
                "identityToken": "XBL3.0 x=%s;%s" % (uhs, xsts_token),
                "ensureLegacyEnabled": True
            }

            res = session.post("https://api.minecraftservices.com/authentication/login_with_xbox", headers=headers,
                               json=data)
            res = res.json()
            # print(res)
            bearer_token = res["access_token"]

            # ----- try to change name
            headers2 = {
                "Accept": "application/json",
                "Authorization": f"Bearer {bearer_token}"
            }
            data = {
                "profileName": f"{name}"
            }
            time.sleep(1)

            res = requests.post(url, headers=headers2, json=data)
            print("status: %s" % (res.status_code), res.json())
            if res.status_code == 200:
                create_log("INFO", "Name changed!\n%s" % (res.json()), "")
                return "CHANGED", bearer_token
            else:
                # create_log("INFO", "Name not changed.\n%s" % (str(res.json())))
                return "NOT-CHANGED", bearer_token
        else:
            return "INDEX-ERROR", "no-token"

    except OSError as oErr:
        print("PROXY ERROR")
        # create_log("PROXY-ERROR", "Tunnel connection failed: 407 Proxy Authentication Required")
        create_log("WARNING", "Proxy Error", "%s" % (oErr))
        return "PROXY-ERROR"

    except Exception as error:
        print("[-] Something went wrong!")
        print("%s" % (error))
        create_log("ERROR", "Something went wrong!\n%s" % (error), "")
        return "ERROR"


def single_name(email, pwd, name):
    global account_success
    token = ""
    name_to_snipe = name
    req_freq = 300
    while True:
        print(email, name_to_snipe, "[single name]")
        if token != "":
            print("[Token auth]")
            res = token_login(token, name_to_snipe)
            if res == "CHANGED":
                account_success.append([email, name_to_snipe])
                break
            elif res == "CHANGE-AUTH-METHOD":
                print("[Microsoft auth]")
                res2, tk = microsoft_login(email, pwd, name_to_snipe)
                if res2 == "CHANGED":
                    account_success.append([email, name_to_snipe])
                    break
                elif res2 == "NOT-CHANGED":
                    token = tk
                elif res2 == "INDEX-ERROR":
                    print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
        else:
            print("[Microsoft auth]")
            res, tk = microsoft_login(email, pwd, name_to_snipe)
            if res == "CHANGED":
                account_success.append([email, name_to_snipe])
                break
            elif res == "INDEX-ERROR":
                print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")

        time.sleep(req_freq)



def multi_name(check_emails):
    # account_progression_multi = [[tk,email,pwd,n,[n1,..,nn], status],[tk,email,pwd,n,[n1,..,nn], status],...]
    global account_progression_multi, account_success
    get_data(check_emails, 1)
    current_account = []
    disable_progression = False
    req_freq = 180  # 3 min
    progression = 0

    while True:
        if progression >= len(account_progression_multi):
            progression = 0
            print("[*] Restarting account list")

        current_account = account_progression_multi[progression]
        token = current_account[0]
        email = current_account[1]
        password = current_account[2]
        name_number = current_account[3]
        if name_number >= len(current_account[4]):
            account_progression_multi[progression][3] = 0
            name_number = 0

        name_to_snipe = current_account[4][name_number]
        disable_progression = False

        print("\n")
        print(email, name_to_snipe, "[f1 %s %s]" % (progression, name_number))

        if token != "":
            print("[Token auth]")
            res = token_login(token, name_to_snipe)
            if res == "CHANGED":
                account_progression_multi[progression][5] = "changed"
                account_success.append(account_progression_multi[progression])
                account_progression_multi.pop(progression)
            # elif res == "NOT-CHANGED":
            elif res == "CHANGE-AUTH-METHOD":
                print("[Microsoft auth]")
                res2, tk = microsoft_login(email, password, name_to_snipe)
                if res2 == "CHANGED":
                    account_progression_multi[progression][5] = "changed"
                    account_success.append(account_progression_multi[progression])
                    account_progression_multi.pop(progression)
                elif res2 == "NOT-CHANGED":
                    account_progression_multi[progression][0] = tk
                elif res2 == "INDEX-ERROR":
                    print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
                elif res2 == "PROXY-ERROR":
                    disable_progression = True
            elif res == "ERROR":
                print("")  # just do nothing
            elif res == "PROXY-ERROR":
                disable_progression = True

        else:
            print("[Microsoft auth]")
            res, tk = microsoft_login(email, password, name_to_snipe)
            if res == "CHANGED":
                account_progression_multi[progression][5] = "changed"
                account_success.append(account_progression_multi[progression])
                account_progression_multi.pop(progression)
            elif res == "NOT-CHANGED":
                account_progression_multi[progression][0] = tk
            elif res == "INDEX-ERROR":
                print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
            elif res == "PROXY-ERROR":
                disable_progression = True

        if disable_progression:
            time.sleep(120)
        else:
            account_progression_multi[progression][3] = name_number + 1
            progression += 1
            time.sleep(req_freq)

        if account_progression_multi == []:
            break


def multi_name_2(check_emails):
    # account_progression_multi = [[tk,email,pwd,n,[n1,..,nn], status],[tk,email,pwd,n,[n1,..,nn], status],...]
    global account_progression_multi2, account_success
    get_data(check_emails, 3)
    current_account = []
    disable_progression = False
    req_freq = 180  # 3 min
    progression = 0

    while True:
        if progression >= len(account_progression_multi2):
            progression = 0
            print("[*] Restarting account list")

        current_account = account_progression_multi2[progression]
        token = current_account[0]
        email = current_account[1]
        password = current_account[2]
        name_number = current_account[3]
        if name_number >= len(current_account[4]):
            account_progression_multi2[progression][3] = 0
            name_number = 0

        name_to_snipe = current_account[4][name_number]
        disable_progression = False

        print("\n")
        print(email, name_to_snipe, "[f3 %s %s]" % (progression, name_number))

        if token != "":
            print("[Token auth]")
            res = token_login(token, name_to_snipe)
            if res == "CHANGED":
                account_progression_multi2[progression][5] = "changed"
                account_success.append(account_progression_multi2[progression])
                account_progression_multi2.pop(progression)
            # elif res == "NOT-CHANGED":
            elif res == "CHANGE-AUTH-METHOD":
                print("[Microsoft auth]")
                res2, tk = microsoft_login(email, password, name_to_snipe)
                if res2 == "CHANGED":
                    account_progression_multi2[progression][5] = "changed"
                    account_success.append(account_progression_multi2[progression])
                    account_progression_multi2.pop(progression)
                elif res2 == "NOT-CHANGED":
                    account_progression_multi2[progression][0] = tk
                elif res2 == "INDEX-ERROR":
                    print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
                elif res2 == "PROXY-ERROR":
                    disable_progression = True
            elif res == "ERROR":
                print("")  # just do nothing
            elif res == "PROXY-ERROR":
                disable_progression = True

        else:
            print("[Microsoft auth]")
            try:
                res, tk = microsoft_login(email, password, name_to_snipe)
                if res == "CHANGED":
                    account_progression_multi2[progression][5] = "changed"
                    account_success.append(account_progression_multi2[progression])
                    account_progression_multi2.pop(progression)
                elif res == "NOT-CHANGED":
                    account_progression_multi2[progression][0] = tk
                elif res == "INDEX-ERROR":
                    print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
                elif res == "PROXY-ERROR":
                    disable_progression = True
            except ValueError as v_ex:
                print("---ERROR---")
                print(v_ex)

        if disable_progression:
            time.sleep(120)
        else:
            account_progression_multi2[progression][3] = name_number + 1
            progression += 1
            time.sleep(req_freq)

        if account_progression_multi2 == []:
            break


def no_name(check_emails):
    global account_progression_nn, account_success
    get_data(check_emails, 2)
    current_account = []
    disable_progression = False
    req_freq = 480  # 8 min
    progression = 0

    while True:
        if progression >= len(account_progression_nn):
            progression = 0
            print("[*] Restarting account list")

        current_account = account_progression_nn[progression]
        token = current_account[0]
        email = current_account[1]
        password = current_account[2]
        name_number = current_account[3]
        if name_number >= len(current_account[4]):
            account_progression_nn[progression][3] = 0
            name_number = 0

        name_to_snipe = current_account[4][name_number]
        disable_progression = False

        print("\n")
        print(email, name_to_snipe, "[f2 %s %s]" % (progression, name_number))

        print("[Microsoft auth]")
        res, tk = microsoft_login(email, password, name_to_snipe)
        if res == "CHANGED":
            account_progression_nn[progression][5] = "changed"
            account_success.append(account_progression_nn[progression])
            account_progression_nn.pop(progression)
        elif res == "NOT-CHANGED":
            print("")
        elif res == "INDEX-ERROR":
            print("""INDEX ERROR AT 'raw_login_data = res.url.split("#")[1]'""")
        elif res == "PROXY-ERROR":
            disable_progression = True

        if disable_progression:
            time.sleep(120)
        else:
            account_progression_nn[progression][3] = name_number + 1
            progression += 1
            time.sleep(req_freq)

        if account_progression_nn == []:
            break


def main():
    welcome = "M c N S +"
    welcome_art = pyfiglet.figlet_format(welcome, font="colossal")
    welcome_art = welcome_art.replace("                                           \n", "")
    welcome_art += "\t\t\t\t\t\t\t\nMade by Hackerez\n"
    print(welcome_art)
    time.sleep(1)
    # conf = str(input("Config...: "))

    multi_name_list = []

    multi_name_list2 = []

    no_name_list = []

    if multi_name_list != []:
        f1 = threading.Thread(target=multi_name, args=(multi_name_list,))
        f1.start()
        time.sleep(150)
    if no_name_list != []:
        f2 = threading.Thread(target=no_name, args=(no_name_list,))
        f2.start()
    if multi_name_list2 != []:
        time.sleep(150)
        f3 = threading.Thread(target=multi_name_2, args=(multi_name_list2,))
        f3.start()
    time.sleep(75)
    single_name("","","")
    f1.join()
    f2.join()
    f3.join()

    print("\n[+++] Seems impossible but the program ended!")


try:
    main()
except KeyboardInterrupt:
    if account_success:
        txt = ""
        for a in account_success:
            txt += "%s\n" % (a)
        save = open("account-success.txt", "w")
        save.write(txt)
        save.close()
    print("\n[-] Bye bye!")

except Exception as main_error:
    if account_success:
        txt = ""
        for a in account_success:
            txt += "%s\n" % (a)
        save = open("account-success.txt", "w")
        save.write(txt)
        save.close()
    print("\nEXCEPTION:", main_error)
    create_log("ERROR", main_error, "")
    raise
