import pyshark
import binascii
import qiskit
import pickle
from bitstring import BitArray


QUANLENG = 4


key = ""
cap = pyshark.FileCapture('cap2.pcapng')


def decrypt_msg(enckey: BitArray, msg: BitArray):
    res = BitArray()
    for i in range(msg.len):
        tmp = enckey[i] ^ msg[i]
        res.append("0b" + str(int(tmp)))
    return res


def recv_quantum(quantum_state: list):
    # Load state
    quantum = [qiskit.QuantumCircuit(1, 1) for _ in range(4)]
    # Recover quantum
    for i in range(4):
        real_part_a = quantum_state[i][0].real
        real_part_b = quantum_state[i][1].real
        if real_part_a == 1.0 and real_part_b == 0.0:
            continue
        elif real_part_a == 0.0 and real_part_b == 1.0:
            quantum[i].x(0)
        elif real_part_a > 0.7 and real_part_b > 0.7:
            quantum[i].h(0)
        else:
            quantum[i].x(0)
            quantum[i].h(0)
    return quantum


def measure(receiver_bases: list, quantum: list):
    # Change quantum bit
    for i in range(4):
        if receiver_bases[i]:
            quantum[i].h(0)
            quantum[i].measure(0, 0)
        else:
            quantum[i].measure(0, 0)
        quantum[i].barrier()
    # Execute
    backend = qiskit.Aer.get_backend("statevector_simulator")
    result = qiskit.execute(quantum, backend).result().get_counts()
    return result


def get_key(qubits: list, bases: list, compare_result: list):
    measure_result = measure(bases, qubits)
    for i in range(4):
        if compare_result[i]:
            tmp_res = list(measure_result[i].keys())
            global key
            key += str(tmp_res[0])


if __name__ == "__main__":
    key_len = pickle.loads(cap[0].data.data.binary_value)
    i = 1
    while i < 567:
        if int(cap[i+1].data.len) == 15:
            i += 2
            continue
        quantum_state = pickle.loads(cap[i].data.data.binary_value)
        quantum = recv_quantum(quantum_state)
        bob_bases = pickle.loads(cap[i+1].data.data.binary_value)
        alice_judge = pickle.loads(cap[i+2].data.data.binary_value)
        get_key(quantum, bob_bases, alice_judge)
        i += 3
    key = key[:key_len]
    msg = BitArray(pickle.loads(cap[567].data.data.binary_value))
    plaintext = decrypt_msg(BitArray("0b"+key), msg)
    print(plaintext.tobytes())
