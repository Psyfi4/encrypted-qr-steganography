import streamlit as st
from PIL import Image
import numpy as np
import base64
import qrcode
import io
import cv2
from pyzbar.pyzbar import decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES encryption/decryption key (must be 16 bytes)
AES_KEY = b'MySecretKey12345'  # 16-char key

def encrypt_data(data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def decrypt_data(enc_data):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(enc_data)), AES.block_size)
    return decrypted.decode()

def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

def hide_qr_in_image(cover_img, qr_img):
    cover_data = np.array(cover_img.convert("RGB"))
    qr_data = np.array(qr_img.convert("1"))

    qr_bits = qr_data.flatten()
    qr_bits = [1 if bit == 0 else 0 for bit in qr_bits]  # Invert black to 1

    height, width, _ = cover_data.shape
    total_pixels = height * width

    if len(qr_bits) > total_pixels:
        raise ValueError(f"Cover image too small. Needs {len(qr_bits)} pixels, has {total_pixels}.")

    idx = 0
    for i in range(height):
        for j in range(width):
            if idx < len(qr_bits):
                pixel_value = int(cover_data[i, j, 0])
                bit = qr_bits[idx]
                cover_data[i, j, 0] = (pixel_value & ~1) | bit
                idx += 1

    stego_img = Image.fromarray(cover_data.astype(np.uint8))
    return stego_img

def extract_qr_from_image(stego_img):
    cover_data = np.array(stego_img.convert("RGB"))
    height, width, _ = cover_data.shape

    bits = []
    for i in range(height):
        for j in range(width):
            bits.append(cover_data[i, j, 0] & 1)

    qr_size = int(np.sqrt(len(bits)))
    bits = bits[:qr_size * qr_size]
    qr_array = np.array(bits, dtype=np.uint8).reshape((qr_size, qr_size)) * 255
    qr_img = Image.fromarray(qr_array).convert("1")
    return qr_img

# Streamlit UI
st.title("🔐 Encrypted QR Code Steganography")

mode = st.radio("Select Mode", ["🔏 Encrypt & Hide", "🔓 Extract & Decrypt"])

if mode == "🔏 Encrypt & Hide":
    user_input = st.text_input("Enter secret message:")
    cover_file = st.file_uploader("Upload a cover image (preferably large)", type=["png", "jpg", "jpeg"])

    if st.button("Generate Stego Image"):
        if user_input and cover_file:
            encrypted = encrypt_data(user_input)
            qr_img = generate_qr_code(encrypted)
            cover_img = Image.open(cover_file)

            try:
                stego_img = hide_qr_in_image(cover_img, qr_img)
                st.success("✅ Message embedded successfully!")
                st.image(stego_img, caption="Stego Image")

                buf = io.BytesIO()
                stego_img.save(buf, format="PNG")
                byte_im = buf.getvalue()
                b64 = base64.b64encode(byte_im).decode()
                href = f'<a href="data:file/png;base64,{b64}" download="stego_image.png">Download Stego Image</a>'
                st.markdown(href, unsafe_allow_html=True)
            except Exception as e:
                st.error(f"❌ Error: {e}")
        else:
            st.warning("Please provide both a message and cover image.")

elif mode == "🔓 Extract & Decrypt":
    stego_file = st.file_uploader("Upload stego image", type=["png", "jpg", "jpeg"])
    if st.button("Extract Message"):
        if stego_file:
            stego_img = Image.open(stego_file)
            try:
                qr_img = extract_qr_from_image(stego_img)

                qr_img_cv = np.array(qr_img)
                decoded = decode(cv2.cvtColor(qr_img_cv, cv2.COLOR_GRAY2BGR))
                if decoded:
                    encrypted_data = decoded[0].data.decode()
                    message = decrypt_data(encrypted_data)
                    st.success("✅ Decrypted Message:")
                    st.code(message)
                else:
                    st.error("❌ Could not decode QR code from image.")
            except Exception as e:
                st.error(f"❌ Error: {e}")
        else:
            st.warning("Please upload a stego image.")
