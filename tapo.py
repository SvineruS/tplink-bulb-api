import base64
import hashlib
import json
import time
from base64 import b64decode

import pkcs7
import requests
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA


class BulbException(Exception):
    ERROR_CODES = {
        -1003: "JSON formatting error",
        -1010: "Invalid Public Key Length",
        -1301: "Too many requests",
        -1501: "Invalid Request or Credentials",
        1002: "Incorrect Request",
    }

    def __init__(self, error_code: int) -> None:
        self.error_code = error_code

    def __str__(self):
        return f"Error Code: {self.error_code}, {self.ERROR_CODES.get(self.error_code, 'Unknown error')}"


class Bulb:
    def __init__(self, ip, email, password):
        self.ip = ip

        self.email = _TpLinkCipher.mime_encoder(hashlib.sha1(email.encode("UTF-8")).hexdigest().encode("utf-8"))
        self.password = _TpLinkCipher.mime_encoder(password.encode("utf-8"))

        keys = RSA.generate(1024)

        def get_cipher(encrypted_key):
            cipher = PKCS1_v1_5.new(RSA.importKey(keys.exportKey("PEM")))
            do_final = cipher.decrypt(b64decode(encrypted_key.encode("UTF-8")), None)
            if do_final is None:
                raise ValueError("Decryption failed!")
            arr = bytearray(do_final)
            return _TpLinkCipher(arr[:16], arr[16:])

        r = requests.post(f"http://{self.ip}/app",
                          json=self._payload("handshake", key=keys.publickey().exportKey("PEM").decode("utf-8")))
        self.cipher = get_cipher(self._parse_res(r.json())["key"])
        self.cookie = r.headers["Set-Cookie"][:-13]

        self.token = None  # self.request() use self.token :)
        self.token = self.request("login_device", username=self.email, password=self.password)["token"]

    def power(self, status):
        self.request("set_device_info", device_on=status)

    def set_brightness(self, brightness):
        self.request("set_device_info", brightness=brightness)

    def set_color_temp(self, colortemp):
        self.request("set_device_info", color_temp=colortemp)

    def set_color(self, hue, saturation):
        self.request("set_device_info", hue=hue, saturation=saturation)

    def get_device_info(self):
        return self.request("get_device_info")

    def request(self, method, **params):
        url = f"http://{self.ip}/app?token={self.token}"
        payload = self._payload(method, requestTimeMils=int(time.time() * 1000), **params)
        encrypted_payload = self._payload("securePassthrough", request=self.cipher.encrypt(json.dumps(payload)))

        res = requests.post(url, json=encrypted_payload, headers={"Cookie": self.cookie})
        res = self._parse_res(res.json())["response"]
        res = json.loads(self.cipher.decrypt(res))
        return self._parse_res(res)

    def _payload(self, method, **params):
        return dict(method=method, params=params)

    def _parse_res(self, res):
        if res.get('error_code', 0) != 0:
            raise BulbException(res['error_code'])
        return res.get("result", None)


class _TpLinkCipher:
    def __init__(self, b_arr: bytearray, b_arr2: bytearray):
        self.iv = bytes(b_arr2)
        self.key = bytes(b_arr)

    @staticmethod
    def mime_encoder(to_encode: bytes):
        encoded_list = list(base64.b64encode(to_encode).decode("UTF-8"))
        count = 0
        for i in range(76, len(encoded_list), 76):
            encoded_list.insert(i + count, '\r\n')
            count += 1
        return ''.join(encoded_list)

    def encrypt(self, data):
        data = pkcs7.PKCS7Encoder().encode(data).encode("UTF-8")
        encrypted = self.cipher().encrypt(data)
        return _TpLinkCipher.mime_encoder(encrypted).replace("\r\n", "")

    def decrypt(self, data: str):
        data = base64.b64decode(data.encode("UTF-8"))
        pad_text = self.cipher().decrypt(data).decode("UTF-8")
        return pkcs7.PKCS7Encoder().decode(pad_text)

    def cipher(self):
        return AES.new(self.key, AES.MODE_CBC, self.iv)
