from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import smtplib
from email.mime.text import MIMEText

# Генерація ключів для ЕЦП
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Збереження публічного ключа (можливо, використовуючи сертифікат)
public_key_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Функція для підпису повідомлення ЕЦП
def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Функція для перевірки ЕЦП при отриманні повідомлення
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Відправка зашифрованого та підписаного повідомлення по електронній пошті
def send_signed_email(sender_email, recipient_email, subject, body, private_key):
    # Збереження публічного ключа в повідомленні
    message_with_key = f"Public Key:\n{public_key_bytes.decode('utf-8')}\n\n{body}"

    # Підписання повідомлення
    signature = sign_message(message_with_key, private_key)

    # Формування поштового повідомлення
    msg = MIMEText(message_with_key)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = recipient_email

    # Додаємо ЕЦП в заголовок повідомлення
    msg.add_header('X-SMTPAPI', f'SMTPAPI {{"x-signature": "{signature.decode("utf-8")}"}}')


    # Відправка електронної пошти
    server = smtplib.SMTP('your_smtp_server.com', 587)
    server.starttls()
    server.login(sender_email, 'your_email_password')
    server.sendmail(sender_email, [recipient_email], msg.as_string())
    server.quit()

# Отримання та перевірка ЕЦП при отриманні повідомлення
def receive_signed_email(email_content, public_key):
    # Витягуємо публічний ключ з повідомлення
    lines = email_content.split('\n')
    public_key_bytes_received = lines[1].encode('utf-8')

    # Перевірка, чи публічні ключі співпадають
    if public_key_bytes_received != public_key_bytes:
        raise Exception("Public keys do not match.")

    # Видалення публічного ключа з повідомлення
    message = '\n'.join(lines[2:])

    # Витягування ЕЦП з заголовка повідомлення
    signature_received = lines[-1].split('"')[1]

    # Перевірка ЕЦП
    if verify_signature(message, signature_received.encode('utf-8'), public_key):
        print("Signature is valid.")
    else:
        print("Signature is invalid.")
