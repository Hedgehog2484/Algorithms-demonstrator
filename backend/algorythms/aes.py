from typing import Tuple, List, Dict


class AES:
    """
    Реализация алгоритма шифрования AES.
    """
    def __init__(self, cipher_key: int, sbox: tuple):
        self.key = cipher_key
        self.sbox = sbox

    def get_64bit_blocks(self, plain_text: bytes) -> List[bytes]:
        pass

    def encrypt(self, open_text_block: int) -> Tuple[int, List[Dict[str, bytes]]]:
        pass
