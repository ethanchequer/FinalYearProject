from flask import Blueprint

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return "<p>Login</p>"

@auth.route('/logout')
def logout():
    return "<p>Logout</p>"

@auth.route('/register')
def register():
    return "<p>Register</p>"

# Old benchmarking function for OQS algorithms
def benchmark():
    data = request.json # Gets the JSON data sent in the POST request
    algorithm = data.get("algorithm") # Gets the selected algorithm from the JSON data

    if not algorithm:
        return jsonify({"error": "No algorithm selected"}), 400
    #  If no algorithm is provided, returns a JSON response with an error message and status code 400 (Bad Request)

    result = benchmark(algorithm) # Calls the benchmark() function with the selected algorithm
    return jsonify(result) # Returns a JSON response with the benchmarking results



# New benchmarking function for PQC algorithms
def benchmark_pqc(algorithm):
    try:
        start_time = time.time()

        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
        elif algorithm == "Dilithium2":
            kem = oqs.Signature("Dilithium2")
        elif algorithm == "SPHINCS+-128s":
            kem = oqs.Signature("SPHINCS+-128s")
        else:
            return {"error": "Invalid algorithm"}

        # Perform cryptographic operations
        if isinstance(kem, oqs.KeyEncapsulation):  # Key Encapsulation (Kyber512)
            public_key = kem.generate_keypair()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            shared_secret_dec = kem.decap_secret(ciphertext)

        elif isinstance(kem, oqs.Signature):  # Digital Signature (Dilithium2, SPHINCS+)
            message = b"Test message"
            public_key = kem.generate_keypair()
            signature = kem.sign(message)
            is_valid = kem.verify(message, signature, public_key)

        # Benchmark results
        execution_time = time.time() - start_time
        return {
            "algorithm": algorithm,
            "time": round(execution_time, 4),
            "power": "N/A",  # Add power monitoring later
        }

    except Exception as e:
        return {"error": str(e)}
