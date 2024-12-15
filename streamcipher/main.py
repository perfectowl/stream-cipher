import tkinter as tk
from tkinter import ttk
import random


# Генерация ключевого потока (корень n-ной степени числа m)
def generate_root_key_stream(length):
    key_stream = []
    for i in range(length):
        m = random.randint(1, 100)
        n = random.randint(2, 10)
        value = int(m ** (1 / n) * 256) % 256  # Корень n-ной степени
        key_stream.append(value)
    return key_stream


# Глобальные переменные для ключевой гаммы
last_key_stream = None
last_encrypted_text = None


# Генерация гаммы
def generate_gamma():
    global last_key_stream
    text = message_input.get("1.0", tk.END).strip()
    if not text:
        result_output.set("Введите сообщение для генерации гаммы!")
        return
    try:
        last_key_stream = generate_root_key_stream(len(text))  # Генерация ключевого потока
        result_output.set(f"Гамма сгенерирована! Длина гаммы: {len(last_key_stream)}")
    except Exception as e:
        result_output.set(f"Ошибка: {e}")


# Шифрование/дешифрование с использованием XOR
def xor_cipher(text, key_stream):
    return ''.join(chr(ord(c) ^ k) for c, k in zip(text, key_stream))


# Шифрование сообщения
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
        last_encrypted_text = encrypted_text  # Сохраняем зашифрованное сообщение
    except Exception as e:
        result_output.set(f"Ошибка: {e}")


# Дешифрование сообщения
def decrypt_message():
    text = encrypted_input.get("1.0", tk.END).strip()
    if not text:
        decrypted_output.set("Введите зашифрованное сообщение!")
        return
    if not last_key_stream or len(last_key_stream) < len(text):
        decrypted_output.set("Сначала сгенерируйте гамму, соответствующую сообщению!")
        return
    try:
        decrypted_text = xor_cipher(text, last_key_stream)  # Дешифруем с той же гаммой
        decrypted_output.set(decrypted_text)
    except Exception as e:
        decrypted_output.set(f"Ошибка: {e}")


# Функция копирования текста в буфер обмена
def copy(content):
    root.clipboard_clear()
    root.clipboard_append(content)
    root.update()


# Функция вставки текста из буфера обмена
def paste(entry):
    entry.delete("1.0", tk.END)
    entry.insert("1.0", root.clipboard_get())


# Создание окна приложения
root = tk.Tk()
root.title("Поточный шифр с использованием XOR")
root.geometry("600x850")  # Увеличение окна для длинных сообщений

# Ввод сообщения
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

# Кнопка для шифрования
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
