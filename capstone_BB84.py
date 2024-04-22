import cirq
import numpy as np

#Step 1: Mr. Krabs generates qubits and chooses random bases (BB84)
def mr_krabs_prepare_qubits(num_qubits):
    qubits = cirq.LineQubit.range(num_qubits)
    bases = np.random.choice(['Z', 'X'], size=num_qubits)
    circuit = cirq.Circuit()

    # Mr. Krabs prepares qubits according to the bases
    for qubit, base in zip(qubits, bases):
        if base == 'X':
            circuit.append(cirq.H(qubit))  # Hadamard Base for X
        # In base Z, the default state is |0>

    return qubits, bases, circuit

# Step 2: Spongebob receives qubits and chooses bases to measure
def spongebob_measure_qubits(qubits, bases):
    # Use the same circuit for consistency
    circuit = cirq.Circuit()
    spongebob_bases = np.random.choice(['Z', 'X'], size=len(qubits))

    # Spongebob mide los qubits según sus bases
    for qubit, base in zip(qubits, spongebob_bases):
        if base == 'X':
            circuit.append(cirq.H(qubit))  # Hadamard base for X before measuring
        circuit.append(cirq.measure(qubit, key=f'qubit_{qubit}'))

    return spongebob_bases, circuit

#Step 3: Quantum Noise Simulation
def add_quantum_noise(circuit, noise_level=0.05):
    # Simulate depolarization noise at the end of the circuit
    for op in circuit.all_operations():
        circuit.append(cirq.depolarize(noise_level))

# Step 4: Comparison of bases and reconciliation of the quantum key
def reconcile_key(mr_krabs_bases, spongebob_bases, measurement_results):
    shared_key = []

    # Filter results where bases match
    for i, (mr_krabs_base, spongebob_base) in enumerate(zip(mr_krabs_bases, spongebob_bases)):
        if mr_krabs_base == spongebob_base:
            # Extract measurement result
            shared_key.append(int(measurement_results[f'qubit_{i}'][0]))

    return shared_key

# Step 5: Key verification (parity, authenticity)
def verify_key(shared_key):
    # Verify if the key is secure (you can add other verification methods)
    if len(set(shared_key)) == 1:
        return False  # Unsecure key (all bits the same)
    return True

# Step 6: Encrypt and decrypt message using QKD key
def encrypt_message(message, key):
    # Convert message to binary using BCD (Binary Decimal Code)
    message_bits = [int(b) for b in ''.join(f'{ord(char):08b}' for char in message)]
    encrypted_bits = [(m ^ k) for m, k in zip(message_bits, key)]

    return ''.join(map(str, encrypted_bits))

def decrypt_message(encrypted_message, key):
    encrypted_bits = [int(b) for b in encrypted_message]
    decrypted_bits = [(e ^ k) for e, k in zip(encrypted_bits, key)]

    # Convert from binary to ASCII to get the original message
    byte_str = ''.join(str(b) for b in decrypted_bits)
    ascii_message = ''.join(chr(int(byte_str[i:i + 8], 2)) for i in range(0, len(byte_str), 8))

    return ascii_message

#Step 7: Interception Simulation by Plankton
def simulate_plankton_interception(qubits):
    # Plankton can intercept some qubits
    intercepted_qubits = qubits[:-1]  # Plankton intercepts all but the last one
    return intercepted_qubits

# Example of using the BB84 protocol with a Krabby Patty theme
if __name__ == "__main__":
    num_qubits = 16  # Quantum key length

    # Mr. Krabs prepares qubits and chooses bases
    qubits, mr_krabs_bases, mr_krabs_circuit = mr_krabs_prepare_qubits(num_qubits)

    # Quantum noise simulation to reflect the environment
    add_quantum_noise(mr_krabs_circuit, noise_level=0.05)  # sim a little by noise

    # Spongebob chooses bases and measures qubits
    spongebob_bases, spongebob_circuit = spongebob_measure_qubits(qubits, mr_krabs_bases)

    # Spongebob measurement simulation
    simulator = cirq.Simulator()
    measurement_results = simulator.run(spongebob_circuit, repetitions=1).data

    # Reconcile to get the final shared key
    shared_key = reconcile_key(mr_krabs_bases, spongebob_bases, measurement_results)

    # Verify key security
    is_key_secure = verify_key(shared_key)

    if is_key_secure:
        print("Shared key:", shared_key)

        # Original message representing the secret formula (ASCII example)
        message = "the secret is NOTHING!!"  #mesage to use

        # Encrypt the message using the shared key
        encrypted_message = encrypt_message(message, shared_key)

        # Decrypt the message using the same key
        decrypted_message = decrypt_message(encrypted_message, shared_key)

        print("Encrypted message:", encrypted_message)
        print("Decrypted message:", decrypted_message)
    else:
        print("Mr. Krabs! The shared key is not secure. Plankton could have intercepted.")
