import streamlit as st
import numpy as np
import cv2
import qrcode
from PIL import Image
from pyzbar.pyzbar import decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import io

# --- AES Encryption / Decryption ---
def encrypt_data(data, key):
    cipher = AES.new(key.encode(), AES.MODE_CBC, iv=b'1234567890123456')
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(ct_bytes).decode()

def decrypt_data(enc_data, key="thisisasecretkey"):  # Default key
    try:
        enc = base64.b64decode(enc_data)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv=b'1234567890123456')
        pt = unpad(cipher.decrypt(enc), AES.block_size)
        return pt.decode()
    except Exception as e:
        return f"Decryption Error: {e}"

# --- QR Code Generation ---
def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=1)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    return img

# --- Steganography: Hide QR in Cover Image ---
def hide_qr_in_image(cover_img, qr_img):
    cover_img = cover_img.convert("RGB")
    qr_img = qr_img.resize(cover_img.size).convert("1")  # Binary QR
    cover_data = np.array(cover_img)
    qr_data = np.array(qr_img)

    # Embed each QR pixel's bit into LSB of red channel
    for i in range(cover_data.shape[0]):
        for j in range(cover_data.shape[1]):
            bit = 1 if qr_data[i, j] == 0 else 0  # black pixel = 1
            red_channel = cover_data[i, j, 0]
            # Safely set LSB to bit
            red_channel = (red_channel & 0b11111110) | bit
            cover_data[i, j, 0] = red_channel

    stego_img = Image.fromarray(cover_data)
    return stego_img

# --- Extract QR from Stego Image ---
def extract_qr_from_image(stego_img):
    stego_data = np.array(stego_img)
    qr_data = np.zeros((stego_data.shape[0], stego_data.shape[1]), dtype=np.uint8)

    for i in range(stego_data.shape[0]):
        for j in range(stego_data.shape[1]):
            bit = stego_data[i, j, 0] & 1
            qr_data[i, j] = 0 if bit == 1 else 255

    qr_img = Image.fromarray(qr_data)
    return qr_img

# --- Streamlit App ---
st.set_page_config(page_title="🔐 Encrypted QR Steganography", layout="centered")
st.title("🔐 Encrypted QR Code Steganography")
st.write("Securely hide and decode encrypted messages inside images using QR codes and steganography.")

mode = st.radio("Choose mode:", ["🔏 Encrypt & Hide", "🔓 Extract & Decrypt"])

if mode == "🔏 Encrypt & Hide":
    message = st.text_area("Enter secret message")
    password = st.text_input("Enter 16-character AES password", type="password", max_chars=16)
    cover_image = st.file_uploader("Upload cover image", type=["jpg", "png", "jpeg"])

    if st.button("Generate Stego Image"):
        if not (message and password and cover_image):
            st.error("❗ All fields are required.")
        elif len(password) != 16:
            st.error("❗ AES key must be exactly 16 characters.")
        else:
            encrypted_data = encrypt_data(message, password)
            qr_img = generate_qr_code(encrypted_data)
            cover_img = Image.open(cover_image)
            stego_img = hide_qr_in_image(cover_img, qr_img)

            st.success("✅ Stego image created. Download below:")
            img_bytes = io.BytesIO()
            stego_img.save(img_bytes, format='PNG')
            st.download_button("📥 Download Stego Image", data=img_bytes.getvalue(), file_name="stego.png")

elif mode == "🔓 Extract & Decrypt":
    stego_file = st.file_uploader("Upload stego image", type=["png", "jpg", "jpeg"])
    password = st.text_input("Enter AES password used for encryption", type="password")

    if st.button("Extract Message"):
        if not (stego_file and password):
            st.error("❗ Both image and password are required.")
        else:
            try:
                stego_img = Image.open(stego_file)
                qr_img = extract_qr_from_image(stego_img)

                qr_img_cv = np.array(qr_img.convert("L"))  # Convert to grayscale (uint8)
                decoded = decode(cv2.cvtColor(qr_img_cv, cv2.COLOR_GRAY2BGR))
                if decoded:
                    encrypted_data = decoded[0].data.decode()
                    message = decrypt_data(encrypted_data, password)
                    st.success("✅ Decrypted Message:")
                    st.code(message)
                else:
                    st.error("❌ Could not decode QR code from image.")
            except Exception as e:
                st.error(f"❌ Error: {e}")
