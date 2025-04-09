# app.py - Streamlit Web App for Encrypted QR Code Steganography

import streamlit as st
from PIL import Image
import numpy as np
import base64
import qrcode
import cv2
from pyzbar.pyzbar import decode
from Crypto.Cipher import AES

# AES Encryption/Decryption

def pad(text):
    pad_len = 16 - len(text) % 16
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message).encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encrypted, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted))
    return unpad(decrypted.decode())

# QR Functions

def generate_qr(data):
    qr = qrcode.make(data)
    return qr

def decode_qr(image_path):
    img = cv2.imread(image_path)
    decoded = decode(img)
    return decoded[0].data.decode() if decoded else None

# LSB Steganography

def hide_qr_in_image(cover_img, qr_img):
    cover = cover_img.convert("RGB")
    qr = qr_img.convert("1")

    cover_data = np.array(cover)
    qr_data = np.array(qr.resize(cover.size))

    for i in range(qr_data.shape[0]):
        for j in range(qr_data.shape[1]):
            bit = qr_data[i, j] // 255
            cover_data[i, j, 0] = (cover_data[i, j, 0] & ~1) | bit

    result = Image.fromarray(cover_data)
    return result

def extract_qr_from_image(stego_img):
    stego = stego_img.convert("RGB")
    data = np.array(stego)
    size = data.shape[0]

    recovered = np.zeros((size, size), dtype=np.uint8)
    for i in range(size):
        for j in range(size):
            bit = data[i, j, 0] & 1
            recovered[i, j] = 255 * bit

    return Image.fromarray(recovered)

# Streamlit UI
st.set_page_config(page_title="Encrypted QR Code Steganography", layout="centered")
st.title("🔐 Encrypted QR Code Steganography")

menu = st.sidebar.radio("Choose Option", ["Encode Message", "Decode Image"])

if menu == "Encode Message":
    st.subheader("🔏 Hide Encrypted Message in Image")
    
    message = st.text_area("Enter your secret message")
    password = st.text_input("Enter 16-char AES password", type="password")
    uploaded_cover = st.file_uploader("Upload a cover image (PNG/JPEG)", type=["png", "jpg", "jpeg"])

    if st.button("🔐 Encode and Generate Stego Image"):
        if not uploaded_cover or not message or not password:
            st.warning("Please provide all required inputs.")
        elif len(password) != 16:
            st.error("Password must be exactly 16 characters long.")
        else:
            key = password.encode()
            encrypted = encrypt_message(message, key)
            qr_img = generate_qr(encrypted)
            cover_img = Image.open(uploaded_cover)

            stego_img = hide_qr_in_image(cover_img, qr_img)
            st.image(stego_img, caption="Stego Image with Hidden Encrypted QR")

            stego_img.save("stego_output.png")
            with open("stego_output.png", "rb") as f:
                btn = st.download_button("💾 Download Stego Image", f, file_name="stego_output.png")

elif menu == "Decode Image":
    st.subheader("🕵️ Extract and Decrypt Message from Stego Image")
    uploaded_stego = st.file_uploader("Upload stego image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter AES password", type="password")

    if st.button("🧩 Decode Message"):
        if not uploaded_stego or not password:
            st.warning("Please provide both inputs.")
        elif len(password) != 16:
            st.error("Password must be exactly 16 characters long.")
        else:
            key = password.encode()
            stego_img = Image.open(uploaded_stego)
            qr_extracted = extract_qr_from_image(stego_img)
            qr_extracted.save("extracted_qr.png")
            
            decoded_data = decode_qr("extracted_qr.png")
            if decoded_data:
                try:
                    decrypted = decrypt_message(decoded_data, key)
                    st.success("Decrypted Message:")
                    st.code(decrypted)
                except Exception as e:
                    st.error("Failed to decrypt message. Incorrect key or corrupted QR.")
            else:
                st.error("No QR code found or unreadable.")
