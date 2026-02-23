from flask import Flask, request, jsonify
from database import init_db, save_message, get_messages
from crypto_engine import encrypt, decrypt

app = Flask(__name__)
init_db()

@app.route("/send", methods=["POST"])
def send():
    data = request.json
    sender = data["sender"]
    message = data["message"]

    encrypted = encrypt(message)
    save_message(sender, encrypted)

    return jsonify({"status": "stored securely"})

@app.route("/messages", methods=["GET"])
def messages():
    msgs = get_messages()
    output = []

    for sender, enc_msg in msgs:
        try:
            text = decrypt(enc_msg)
        except:
            text = "Decryption Error"

        output.append({"sender": sender, "message": text})

    return jsonify(output)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
