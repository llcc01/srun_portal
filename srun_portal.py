#!/usr/bin/env python3

from requests import Session
from dotenv import load_dotenv
import os
from pprint import pprint

from srun_encrypt import get_base64, get_sha1, get_xencode, md5_encrypt

load_dotenv(override=True)

GW_BASE_URL = os.getenv("GW_BASE_URL")
if GW_BASE_URL is None:
    print("GW_BASE_URL is not set")
    exit(1)

UA = os.getenv(
    "UA",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
)

s = Session()
s.headers = {"User-Agent": UA}

CALLBACK_NAME = "jQuery"
ACID = "1"
ENC_VER = "srun_bx1"
TYPE = "1"
N = "200"
OS = "Linux"
NAME = "Linux"
DOUBLE_STACK = "0"


def srun_portal_message():
    res = s.get(f"{GW_BASE_URL}/v2/srun_portal_message", params={"per-page": 100})
    return res.json().get("data", None)


def get_callback_data(callback_name: str, raw_str: str) -> dict:
    import re
    import json

    m = re.findall(f"{callback_name}\\((.*)\\)", raw_str)
    return json.loads(m[0]) if m else None


def srun_portal_user_info():
    res = s.get(
        f"{GW_BASE_URL}/cgi-bin/rad_user_info", params={"callback": CALLBACK_NAME}
    )
    return get_callback_data(CALLBACK_NAME, res.text)


def get_challenge(username: str, ip: str):
    res = s.get(
        f"{GW_BASE_URL}/cgi-bin/get_challenge",
        params={"callback": CALLBACK_NAME, "username": username, "ip": ip},
    )
    return get_callback_data(CALLBACK_NAME, res.text)


def srun_portal(action: str, username: str, hmd5: str, chksum: str, ip: str):
    res = s.get(
        f"{GW_BASE_URL}/cgi-bin/srun_portal",
        params={
            "callback": CALLBACK_NAME,
            "action": action,
            "username": username,
            "password": "{MD5}" + hmd5,
            "os": OS,
            "name": NAME,
            "double_stack": DOUBLE_STACK,
            "chksum": chksum,
            "info": login_info,
            "ac_id": ACID,
            "ip": ip,
            "n": N,
            "type": TYPE,
        },
    )
    return get_callback_data(CALLBACK_NAME, res.text)


def get_login_info(username: str, password: str, ip: str, challenge: str):
    import json

    info_data = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": ACID,
        "enc_ver": ENC_VER,
    }
    login_info = json.dumps(info_data, separators=(",", ":"))
    return "{SRBX1}" + get_base64(get_xencode(login_info, challenge))


def get_check_sum(
    challenge: str,
    username: str,
    hmd5: str,
    ip: str,
    login_info: str,
):
    chk_str = (
        challenge
        + username
        + challenge
        + hmd5
        + challenge
        + ACID
        + challenge
        + ip
        + challenge
        + N
        + challenge
        + TYPE
        + challenge
        + login_info
    )
    return get_sha1(chk_str)


if __name__ == "__main__":
    print("srun_portal tool")

    print()

    msg = srun_portal_message()
    pprint(msg)

    print()

    user_info: dict = srun_portal_user_info()
    # pprint(user_info)
    online_ip = user_info.get("online_ip")
    # print(f"online_ip: {online_ip}")

    username = os.getenv("USERNAME") or input("username: ")
    challenge = get_challenge(username, online_ip).get("challenge")
    # pprint(challenge)

    password = os.getenv("PASSWORD") or input("password: ")
    hmd5 = md5_encrypt(password, challenge)

    login_info = get_login_info(username, password, online_ip, challenge)
    # print(login_info)

    check_sum = get_check_sum(challenge, username, hmd5, online_ip, login_info)
    # print(check_sum)


    print()

    login_res = srun_portal("login", username, hmd5, check_sum, online_ip)
    error_msg = login_res.get("error_msg")
    suc_msg = login_res.get("suc_msg")
    print(suc_msg or error_msg)


    # print()

    # user_info: dict = srun_portal_user_info()
    # pprint(user_info)