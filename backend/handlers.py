import json

from typing import Dict, Any
from fastapi import FastAPI

from algorythms import MagmaReplacement, RSA, AES


async def encrypt_magma(payload: Dict[str, Any]) -> str:
    """
    Шифрование переданных данных с помощью алгоритма `Магма`.
    :param payload: Исходные данные (ключ, s-box, исходный текст).
    :return: Строка формата JSON.
    """
    magma = MagmaReplacement(payload["cipher_key"], payload["sbox"])
    blocks = magma.get_64bit_blocks(payload["open_text"].encode("utf-8"))
    result = []
    for block in blocks:
        r = magma.encrypt(int.from_bytes(block, byteorder="big"))
        result[0] += r[0]
        result[1] += r[1]
    return json.dumps({
        "secret_text": str(result[0]),
        "middle_values": result[1],
        "blocks": blocks
    })


async def encrypt_aes(payload: Dict[str, Any]) -> str:
    """
    Шифрование переданных данных с помощью алгоритма AES.
    :param payload: Исходные данные (ключ, s-box, исходный текст).
    :return: Строка формата JSON.
    """
    aes = AES(payload["cipher_key"], payload["sbox"])
    blocks = aes.get_64bit_blocks(payload["open_text"].encode("utf-8"))
    result = []
    for block in blocks:
        r = aes.encrypt(int.from_bytes(block, byteorder="big"))
        result[0] += r[0]
        result[1] += r[1]
    return json.dumps({
        "secret_text": str(result[0]),
        "middle_values": result[1],
        "blocks": blocks
    })


async def encrypt_rsa(payload: Dict[str, Any]) -> str:
    rsa = RSA()
    pass


def setup_handlers(app: FastAPI) -> None:
    """
    Установка хендлеров.
    :param app: главный объект FastAPI.
    :return: None.
    """
    app.post("/magma/encrypt")(encrypt_magma)
    app.post("/aes/encrypt")(encrypt_aes)
    app.post("/rsa/encrypt")(encrypt_rsa)
