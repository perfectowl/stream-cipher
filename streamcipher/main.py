import tkinter as tk
from tkinter import ttk
import os


word_size = 32  # Размер слова
DEFAULT_ROUNDS = 12  # Количество раундов
KEY_SIZE = 16  # Размер ключа по дефолту

# Константы для расширения ключа
P32 = 0xB7E15163
Q32 = 0x9E3779B9


def shift_left(x, y, size=word_size):
    first = (x << y) & (2 ** size - 1)
    second = x >> (size - y)
    return first | second


def shift_right(x, y, size=word_size):
    first = x >> y
    second = (x << (size - y)) & (2 ** size - 1)
    return first | second


def key_schedule(key, rounds=DEFAULT_ROUNDS):
    L = [int.from_bytes(key[i:i + 4], byteorder='little') for i in range(0, len(key), 4)]
    S = [(P32 + i * Q32) & 0xFFFFFFFF for i in range(2 * (rounds + 1))]
    A = B = i = j = 0
    v = 3 * max(len(L), len(S))
    for _ in range(v):
        A = S[i] = shift_left((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = L[j] = shift_left((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 31)
        i = (i + 1) % len(S)
        j = (j + 1) % len(L)
    return S


def rc5_encrypt(key_stream, S, rounds=DEFAULT_ROUNDS):
    A = int.from_bytes(key_stream[:4], byteorder='little')
    B = int.from_bytes(key_stream[4:], byteorder='little')
    l = word_size
    A = (A + S[0]) % (2**l)
    B = (B + S[1]) % (2**l)
    for i in range(1, rounds + 1):
        A = (shift_left((A ^ B), B % l, l) + S[2 * i]) % (2**l)
        B = (shift_left((B ^ A), A % l, l) + S[2 * i + 1]) % (2**l)
    key_stream = A.to_bytes(4, byteorder='little') + B.to_bytes(4, byteorder='little')
    return key_stream


def generate_rc5_gamma(length, key):
    S = key_schedule(key)
    gamma = []
    i = 0
    for _ in range(length):
        block = (i.to_bytes(8, byteorder='little'))
        encrypted_block = rc5_encrypt(block, S)
        gamma.append(encrypted_block[0])
        i += 1
    return gamma


encryption_key = os.urandom(KEY_SIZE)
last_key_stream = None
last_encrypted_text = None


def generate_gamma():
    global last_key_stream
    text = message_input.get("1.0", tk.END).strip()
    if not text:
        result_output.set("Введите сообщение для генерации гаммы!")
        return
    try:
        length = len(text)
        last_key_stream = generate_rc5_gamma(length, encryption_key)
        result_output.set(f"Гамма сгенерирована! Длина гаммы: {length}")
    except Exception as e:
        result_output.set(f"Ошибка: {e}")


def xor_cipher(text, key_stream):
    return ''.join(chr(ord(c) ^ k) for c, k in zip(text, key_stream))


def encrypt_message():
    global last_encrypted_text
    text = message_input.get("1.0", tk.END).strip()
    if not text:
        result_output.set("Введите сообщение!")
        return
    if not last_key_stream or len(last_key_stream) < len(text):
        result_output.set("Сначала сгенерируйте гамму, соответствующую сообщению!")
        return
    try:
        encrypted_text = xor_cipher(text, last_key_stream)
        result_output.set(encrypted_text)
        last_encrypted_text = encrypted_text
    except Exception as e:
        result_output.set(f"Ошибка: {e}")


def decrypt_message():
    text = encrypted_input.get("1.0", tk.END).strip()
    if not text:
        decrypted_output.set("Введите зашифрованное сообщение!")
        return
    if not last_key_stream or len(last_key_stream) < len(text):
        decrypted_output.set("Сначала сгенерируйте гамму, соответствующую сообщению!")
        return
    try:
        decrypted_text = xor_cipher(text, last_key_stream)
        decrypted_output.set(decrypted_text)
    except Exception as e:
        decrypted_output.set(f"Ошибка: {e}")


def copy(content):
    root.clipboard_clear()
    root.clipboard_append(content)
    root.update()


def paste(entry):
    entry.delete("1.0", tk.END)
    entry.insert("1.0", root.clipboard_get())


root = tk.Tk()
root.title("Поточный шифр с использованием XOR")
root.geometry("600x850")  # Увеличение окна для длинных сообщений


message_frame = ttk.Frame(root)
message_frame.pack(pady=5, fill=tk.X)
ttk.Label(message_frame, text="Введите сообщение для шифрования:").pack(anchor=tk.W)
message_input = tk.Text(message_frame, height=10, wrap=tk.WORD)  # Увеличение высоты для длинных сообщений
message_input.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(message_frame, text="Копировать", command=lambda: copy(message_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(message_frame, text="Вставить", command=lambda: paste(message_input)).pack(side=tk.LEFT, padx=2)

# Кнопка для генерации гаммы
generate_gamma_button = ttk.Button(root, text="Сгенерировать гамму", command=generate_gamma)
generate_gamma_button.pack(pady=5)


encrypt_button = ttk.Button(root, text="Зашифровать!!!1", command=encrypt_message)
encrypt_button.pack(pady=5)

# Поле для вывода зашифрованного текста
result_frame = ttk.Frame(root)
result_frame.pack(pady=5, fill=tk.X)
result_output = tk.StringVar()
result_label = ttk.Label(result_frame, textvariable=result_output, foreground="blue", wraplength=550, anchor=tk.W, justify=tk.LEFT)
result_label.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(result_frame, text="Копировать", command=lambda: copy(result_output.get())).pack(side=tk.LEFT, padx=5)

# Ввод зашифрованного сообщения
encrypted_frame = ttk.Frame(root)
encrypted_frame.pack(pady=5, fill=tk.X)
ttk.Label(encrypted_frame, text="Введите сообщение для дешифрования:").pack(anchor=tk.W)
encrypted_input = tk.Text(encrypted_frame, height=10, wrap=tk.WORD)  # Увеличение высоты для длинных сообщений
encrypted_input.pack(fill=tk.BOTH, padx=5, expand=True)
ttk.Button(encrypted_frame, text="Копировать", command=lambda: copy(encrypted_input.get("1.0", tk.END).strip())).pack(side=tk.LEFT, padx=2)
ttk.Button(encrypted_frame, text="Вставить", command=lambda: paste(encrypted_input)).pack(side=tk.LEFT, padx=2)

# Кнопка для дешифрования
decrypt_button = ttk.Button(root, text="Расшифровать!1!", command=decrypt_message)
decrypt_button.pack(pady=5)

# Поле для вывода расшифрованного текста
decrypted_output = tk.StringVar()
decrypted_label = ttk.Label(root, textvariable=decrypted_output, foreground="green", wraplength=550, anchor=tk.W, justify=tk.LEFT)
decrypted_label.pack(fill=tk.BOTH, padx=5, expand=True)

# Запуск приложения
root.mainloop()
