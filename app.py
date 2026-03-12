"""
RSA Web Application - Flask Backend
=====================================
Cara menjalankan:
    py app.py
Lalu buka browser: http://localhost:5000
"""

from flask import Flask, render_template, request, jsonify, send_file
from rsa_program import (
    generate_rsa_keys,
    export_public_key_pem,
    export_private_key_pem,
    load_public_key_from_pem,
    load_private_key_from_pem,
    encrypt_message,
    decrypt_message,
)
import io

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/generate", methods=["POST"])
def api_generate():
    try:
        data     = request.get_json()
        bits     = int(data.get("bits", 1024))
        priv, pub = generate_rsa_keys(key_size=bits)
        return jsonify({
            "success"    : True,
            "public_key" : export_public_key_pem(pub),
            "private_key": export_private_key_pem(priv),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    try:
        data      = request.get_json()
        plaintext = data.get("plaintext", "").strip()
        key_pem   = data.get("public_key", "").strip()
        if not plaintext:
            return jsonify({"success": False, "error": "Pesan tidak boleh kosong!"}), 400
        if not key_pem:
            return jsonify({"success": False, "error": "Public key tidak boleh kosong!"}), 400
        pub    = load_public_key_from_pem(key_pem)
        cipher = encrypt_message(plaintext, pub)
        return jsonify({"success": True, "ciphertext": cipher})
    except Exception as e:
        return jsonify({"success": False, "error": f"Enkripsi gagal: {str(e)}"}), 400


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    try:
        data      = request.get_json()
        ciphertext = data.get("ciphertext", "").strip()
        key_pem    = data.get("private_key", "").strip()
        if not ciphertext:
            return jsonify({"success": False, "error": "Ciphertext tidak boleh kosong!"}), 400
        if not key_pem:
            return jsonify({"success": False, "error": "Private key tidak boleh kosong!"}), 400
        priv   = load_private_key_from_pem(key_pem)
        result = decrypt_message(ciphertext, priv)
        return jsonify({"success": True, "plaintext": result})
    except Exception as e:
        return jsonify({"success": False, "error": "Dekripsi gagal! Pastikan private key sesuai."}), 400


@app.route("/api/download-key", methods=["POST"])
def api_download_key():
    try:
        data     = request.get_json()
        key_type = data.get("type", "public")   # "public" or "private"
        content  = data.get("content", "")
        filename = "public_key.pem" if key_type == "public" else "private_key.pem"
        buf = io.BytesIO(content.encode("utf-8"))
        buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name=filename,
                         mimetype="application/x-pem-file")
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, port=5000)
