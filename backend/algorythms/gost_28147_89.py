from typing import List, Tuple, Dict


class MagmaReplacement:
    """
    Реализация алгоритма шифрования Гост 28147-89 'Магма' - способ простой замены.
    """
    def __init__(self, key: int):
        self.key = key
        self.sbox = (
            ([3, 5, 6, 1, 0, 8, 14, 10, 2, 11, 9, 12, 13, 4, 7, 15]),
            ([6, 4, 15, 5, 10, 7, 0, 2, 14, 11, 8, 13, 1, 12, 3, 9]),
            ([12, 7, 2, 1, 8, 9, 11, 5, 15, 6, 10, 4, 3, 14, 0, 13]),
            ([6, 10, 5, 14, 1, 4, 15, 7, 12, 11, 2, 9, 8, 3, 13, 0]),
            ([6, 0, 7, 14, 3, 4, 13, 8, 11, 15, 10, 5, 12, 2, 1, 9]),
            ([13, 1, 15, 5, 3, 14, 7, 2, 0, 4, 6, 8, 12, 9, 10, 11]),
            ([9, 14, 4, 2, 8, 10, 15, 6, 0, 12, 5, 13, 3, 11, 7, 1]),
            ([8, 9, 12, 10, 6, 14, 2, 3, 13, 1, 7, 0, 5, 11, 15, 4])
        )

    def get_64bit_blocks(self, plain_text: bytes) -> List[bytes]:
        """
        Эта функция разбивает исходный текст на 64-битные блоки и возвращает список с ними.
        :param plain_text: Открытый текст, который должен быть поделен на блоки.
        :return: Список 64-битных блоков.
        """
        text_lenght = int.from_bytes(plain_text, byteorder="big").bit_length()  # Считаем длину открытого текста.
        if text_lenght % 64 != 0:
            plain_text += b"\x01" * (64 - text_lenght % 64)
        blocks_list = []
        block = b""
        for byte in plain_text:
            if len(block) * 8 == 64:
                blocks_list.append(block)
                block = b""
            block += byte.to_bytes((max(byte.bit_length(), 1) + 7) // 8, byteorder="big")
        return blocks_list

    def _get_subkeys(self) -> List[int]:
        """
        Разбивает 256-битный ключ на 8 подключей и возвращает их списком.
        :return: Список подключей.
        """
        return [(self.key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]  # Разбиение ключа на 8 подключей.

    def _f(self, text_part: int, subkey: int) -> int:
        """
        Функция f(Ai, Xi), используемая в сети Фейстеля.
        :param text_part: 32-битный блок кода, который будет прогоняться через алгоритм.
        :param subkey: Подключ текущего раунда.
        :return:
        """
        crypt_text = text_part ^ subkey
        result = 0
        for step in range(8):
            result |= ((self.sbox[step][(crypt_text >> (4 * step)) & 0b1111]) << (4 * step))
        return ((result << 11) | (result >> (32 - 11))) & 0xFFFFFFFF

    def encrypt(self, open_text_block: int) -> Tuple[int, List[Dict[str, bytes]]]:
        """
        Функция зашифровки 64-битного блока открытого текста. Возвращает зашифрованный блок.
        :param open_text_block: Блок открытого текста, размером 64-бит.
        :return: Число, являющееся результатом шифрования блока.
        """
        subkeys = self._get_subkeys()
        left_part = open_text_block >> 32  # Старшие биты.
        right_part = open_text_block & 0xFFFFFFFF  # Младшие биты.

        middle_values = []

        for i in range(24):  # 24 раунда с ключами К1-К8:
            temp_var = right_part
            right_part = left_part ^ self._f(right_part, subkeys[i % 8])
            left_part = temp_var
            middle_values.append({"left": temp_var, "right": right_part, "subkey": subkeys[i % 8]})
        for i in range(8):  # 8 раундов с ключами K8-K1:
            temp_var = right_part
            right_part = left_part ^ self._f(right_part, subkeys[7 - i])
            left_part = temp_var
            middle_values.append({"left": temp_var, "right": right_part, "subkey": subkeys[7 - i]})
        return (left_part << 32) | right_part, middle_values  # Возвращаем соединенные части блока, промежуточные значения.

    def decrypt(self, close_text: int):
        """
        Функция дешифрования 64-битного блока зашифрованного текста. Возвращает блок изначального текста.
        :param close_text: Зашифрованный блок, размером 64-бит.
        :return: Число, являющееся открытым (исходным) текстом.
        """
        subkeys = self._get_subkeys()
        left_part = close_text >> 32  # Старшие биты.
        right_part = close_text & 0xFFFFFFFF  # Младшие биты.
        # Раунды как при шифровании, но инвертированные:
        for i in range(8):
            temp_var = left_part
            left_part = right_part ^ self._f(left_part, subkeys[i])
            right_part = temp_var
        for i in range(24):
            temp_var = left_part
            left_part = right_part ^ self._f(left_part, subkeys[(7 - i) % 8])
            right_part = temp_var
        return (left_part << 32) | right_part  # Возвращаем блок расшифрованного сообщения.
