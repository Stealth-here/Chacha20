import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import os
import struct

# Rotate left function
def rotate_left(value, shift):
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

# Quarter-round function
def quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotate_left(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotate_left(state[b], 7)

# ChaCha20 block function
def chacha20_block(key, counter, nonce):
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]  # "expand 32-byte k"
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)

    state = constants + list(key_words) + [counter] + list(nonce_words)
    working_state = state[:]

    rounds_output = []

    for round_num in range(10):  # 20 rounds -> 10 column and 10 diagonal
        # Column rounds
        quarter_round(working_state, 0, 4, 8, 12)
        quarter_round(working_state, 1, 5, 9, 13)
        quarter_round(working_state, 2, 6, 10, 14)
        quarter_round(working_state, 3, 7, 11, 15)

        # Diagonal rounds
        quarter_round(working_state, 0, 5, 10, 15)
        quarter_round(working_state, 1, 6, 11, 12)
        quarter_round(working_state, 2, 7, 8, 13)
        quarter_round(working_state, 3, 4, 9, 14)

        # Capture the round state
        rounds_output.append(working_state[:])

    for i in range(16):
        working_state[i] = (working_state[i] + state[i]) & 0xFFFFFFFF

    return struct.pack("<16I", *working_state), rounds_output

# XOR plaintext with keystream
def chacha20_encrypt(key, counter, nonce, plaintext):
    ciphertext = b""
    rounds_data = []
    for i in range(0, len(plaintext), 64):
        block = plaintext[i:i+64]
        keystream, rounds_output = chacha20_block(key, counter + (i // 64), nonce)
        ciphertext += bytes([b ^ k for b, k in zip(block, keystream)])
        rounds_data.extend(rounds_output)
    return ciphertext, rounds_data

def display_round(matrix, round_num):
    for widget in round_display_frame.winfo_children():
        widget.destroy()

    round_label = ttk.Label(round_display_frame, text=f"Round {round_num}", font=("Arial", 14, "bold"))
    round_label.pack(pady=10)

    for i in range(4):
        row_values = matrix[i * 4:(i + 1) * 4]
        row_text = " ".join(f"{hex(value)}" for value in row_values)
        row_label = ttk.Label(round_display_frame, text=row_text, font=("Courier", 12))
        row_label.pack(anchor="w")

def update_round(step):
    global current_round
    current_round += step
    current_round = max(1, min(current_round, len(rounds_data)))
    display_round(rounds_data[current_round - 1], current_round)

def encrypt_and_display():
    global rounds_data, current_round

    try:
        plaintext = plaintext_entry.get("1.0", tk.END).strip()
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")

        # Generate key and nonce
        key = os.urandom(32)
        nonce = os.urandom(12)
        counter = 1

        # Encrypt plaintext
        ciphertext, rounds_data = chacha20_encrypt(key, counter, nonce, plaintext.encode())
        decrypted = chacha20_encrypt(key, counter, nonce, ciphertext)[0].decode()

        # Reset current round
        current_round = 1

        # Display results
        key_label["text"] = f"Key: {key.hex()}"
        nonce_label["text"] = f"Nonce: {nonce.hex()}"
        ciphertext_output.delete("1.0", tk.END)
        ciphertext_output.insert(tk.END, ciphertext.hex())
        decrypted_output.delete("1.0", tk.END)
        decrypted_output.insert(tk.END, decrypted)

        # Display first round
        display_round(rounds_data[0], 1)

    except Exception as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("ChaCha20 Encryption")
root.geometry("800x800")

# Create frames for layout
input_frame = ttk.LabelFrame(root, text="Input")
input_frame.pack(fill="both", padx=10, pady=10)

output_frame = ttk.LabelFrame(root, text="Output")
output_frame.pack(fill="both", expand=True, padx=10, pady=10)

rounds_frame = ttk.LabelFrame(root, text="Rounds")
rounds_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Input section
plaintext_label = ttk.Label(input_frame, text="Enter Plaintext:")
plaintext_label.pack(anchor="w", padx=10, pady=5)

plaintext_entry = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD)
plaintext_entry.pack(fill="both", padx=10, pady=5)

encrypt_button = ttk.Button(input_frame, text="Encrypt", command=encrypt_and_display)
encrypt_button.pack(padx=10, pady=10)

# Output section
key_label = ttk.Label(output_frame, text="Key:")
key_label.pack(anchor="w", padx=10, pady=5)

nonce_label = ttk.Label(output_frame, text="Nonce:")
nonce_label.pack(anchor="w", padx=10, pady=5)

ciphertext_label = ttk.Label(output_frame, text="Ciphertext:")
ciphertext_label.pack(anchor="w", padx=10, pady=5)

ciphertext_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD, state="normal")
ciphertext_output.pack(fill="both", padx=10, pady=5)

plaintext_decrypted_label = ttk.Label(output_frame, text="Decrypted Plaintext:")
plaintext_decrypted_label.pack(anchor="w", padx=10, pady=5)

decrypted_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD, state="normal")
decrypted_output.pack(fill="both", padx=10, pady=5)

# Rounds section
round_display_frame = ttk.Frame(rounds_frame)
round_display_frame.pack(fill="both", expand=True, pady=10)

navigation_frame = ttk.Frame(rounds_frame)
navigation_frame.pack()

prev_button = ttk.Button(navigation_frame, text="Previous", command=lambda: update_round(-1))
prev_button.pack(side="left", padx=5)

next_button = ttk.Button(navigation_frame, text="Next", command=lambda: update_round(1))
next_button.pack(side="left", padx=5)

# Initialize global variables
rounds_data = []
current_round = 1

# Run the application
root.mainloop()
