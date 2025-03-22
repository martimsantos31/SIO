from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os


def generate_key_pair(output_dir, key_name):
    os.makedirs(output_dir, exist_ok=True)

    private_key_path = os.path.join(output_dir, f"{key_name}_private_key.pem")
    public_key_path = os.path.join(output_dir, f"{key_name}_public_key.pem")

    # Gera uma chave privada ECC
    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )  # You can choose a different curve if needed

    # Serializa e salva a chave privada
    with open(private_key_path, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Extrai e serializa a chave pública
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print(f"Chaves geradas com sucesso:")
    print(f"  Chave privada: {private_key_path}")
    print(f"  Chave pública: {public_key_path}")

    return {"private_key": private_key_path, "public_key": public_key_path}


# Teste da função
if __name__ == "__main__":
    generate_key_pair(output_dir="./", key_name="rep_key")
