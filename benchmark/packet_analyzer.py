# packet_analyzer.py

import oqs
from scapy.all import sniff, Raw
import time
from database.db_manager import get_db_connection

class PacketAnalyzer:
    def __init__(self):
        pass

    def apply_pqc(self, algorithm, payload, public_key, sig_obj=None):
        try:
            if algorithm == "Kyber512":
                kem = oqs.KeyEncapsulation("Kyber512")
                ciphertext, _ = kem.encap_secret(public_key)
                return ciphertext
            elif algorithm == "Dilithium2":
                if sig_obj:
                    signature = sig_obj.sign(payload)
                    return signature
            elif algorithm in ["SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
                if sig_obj:
                    signature = sig_obj.sign(payload)
                    return signature
            return None
        except Exception as e:
            print(f"[ERROR] Encryption/Signature failed for {algorithm}: {e}")
            return None

    def capture_packets(self, algorithm, application, packet_count, timeout, interface):
        total_seen = 0
        total_successful = 0
        latency_recorded = False

        if algorithm == "Kyber512":
            kem = oqs.KeyEncapsulation("Kyber512")
            public_key = kem.generate_keypair()
        elif algorithm in ["Dilithium2", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHAKE-128s-simple"]:
            sig_obj = oqs.Signature(algorithm)
            public_key = sig_obj.generate_keypair()
        else:
            public_key = None
            sig_obj = None

        def process_packet(packet):
            nonlocal total_seen, total_successful, latency_recorded
            total_seen += 1

            if packet.haslayer(Raw):
                print(f"[DEBUG] Raw packet captured: {packet.summary()}")
            else:
                print(f"[DEBUG] Packet seen (non-Raw): {packet.summary()}")

            payload = bytes(packet[Raw]) + b"x" * 256 if packet.haslayer(Raw) else b"x" * 256
            start = time.perf_counter()
            encrypted_data = self.apply_pqc(algorithm, payload, public_key, sig_obj)
            enc_time = (time.perf_counter() - start) * 1000

            if encrypted_data:
                total_successful += 1

                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO encrypted_traffic (algorithm, application, original_size, encrypted_size)
                    VALUES (?, ?, ?, ?)
                """, (algorithm, application, len(payload), len(encrypted_data)))

                cursor.execute("""
                    INSERT INTO packet_stats (algorithm, application, original_size, encrypted_size, encryption_time_ms)
                    VALUES (?, ?, ?, ?, ?)
                """, (algorithm, application, len(payload), len(encrypted_data), enc_time))

                cursor.execute("""
                    INSERT INTO packet_latency (algorithm, application, encryption_time_ms)
                    VALUES (?, ?, ?)
                """, (algorithm, application, enc_time))
                latency_recorded = True
                print(f"[DEBUG] Logged latency: {enc_time:.3f}ms for {algorithm} - {application}")
                conn.commit()
                conn.close()

        time.sleep(1)
        sniff(prn=process_packet, count=packet_count, store=False, timeout=timeout, iface=interface)

        loss_rate = ((total_seen - total_successful) / total_seen) if total_seen else 0
        packets_failed = total_seen - total_successful

        if not latency_recorded:
            print(f"[WARN] No latency recorded for {algorithm} - {application}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO packet_loss_stats (
                algorithm, application,
                packets_sent, packets_received,
                packets_failed, packet_loss_rate,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (algorithm, application, total_seen, total_successful, packets_failed, loss_rate))
        conn.commit()
        conn.close()

        return {"total_packets": total_seen, "successful": total_successful, "packet_loss": packets_failed}