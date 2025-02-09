import sys
sys.path.append("/Users/ethanchequer/PyCharmProjects/FlaskProject/.venv/lib/python3.12/site-packages")
import oqs


def list_algorithms():
    """ List available post-quantum algorithms for KEM and signatures """
    print("\nAvailable KEM Algorithms:")
    print(oqs.get_enabled_kem_mechanisms())

    print("\nAvailable Signature Algorithms:")
    print(oqs.get_enabled_sig_mechanisms())


def test_kem(algorithm="Kyber512"):
    """ Perform a Key Encapsulation Mechanism (KEM) test """
    print(f"\nTesting KEM: {algorithm}")

    with oqs.KeyEncapsulation(algorithm) as kem:
        # Generate Keypair (Public and Secret Key)
        public_key = kem.generate_keypair()

        # Encapsulate (Generate shared secret and ciphertext)
        ciphertext, shared_secret_encapsulated = kem.encap_secret(public_key)

        # Decapsulate (Retrieve shared secret from ciphertext)
        shared_secret_decapsulated = kem.decap_secret(ciphertext)

        # Check if the secrets match
        assert shared_secret_encapsulated == shared_secret_decapsulated, "KEM Test Failed!"
        print("KEM Test Passed ✅")


def test_signatures(algorithm="Dilithium2"):
    """ Perform a digital signature test """
    print(f"\nTesting Digital Signature: {algorithm}")

    with oqs.Signature(algorithm) as sig:
        # Generate Keypair (Public and Secret Key)
        public_key = sig.generate_keypair()

        # Sign a message
        message = b"Hello, Post-Quantum World!"
        signature = sig.sign(message)

        # Verify the signature
        valid = sig.verify(message, signature, public_key)
        assert valid, "Signature Test Failed!"
        print("Signature Test Passed ✅")


if __name__ == "__main__":
    list_algorithms()
    test_kem("Kyber512")  # Change to other KEMs like "Kyber768", "NTRU-HPS-2048-509"
    test_signatures("Dilithium2")  # Change to other Sig Schemes like "Falcon-512"



