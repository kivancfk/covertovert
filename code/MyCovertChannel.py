from CovertChannelBase import CovertChannelBase

# additional imports
import time # for measuring transmission time and adding delays, used in the sender
from scapy.all import Dot3, LLC, Raw, sniff  # scapy modules for crafting and sniffing packets.
import scapy.config # scapy configuration module, used to get the default interface


class MyCovertChannel(CovertChannelBase):
    """
    Covert Storage Channel (CSC) via Packet Size Variation (PSV) using LLC (Logical Link Control)

    Encoding Rule:
      - '1' bit => payload length > threshold
      - '0' bit => payload length <= threshold

    We'll send LLC frames with varying payload sizes to encode binary data.
    The receiver will decode the message based on the payload lengths.
    The communication stops when a '.' character is received.
    """

    def __init__(self):
        super().__init__()
        self.decoded_bits = ""
        self.decoded_message = ""
        self.stop_sniffing = False

    def send(self, log_file_name, threshold, threshold_range, llc_header_len, frame_size_dot3,
             epsilon, min_payload_size, dst_mac, delay_ms, min_length, max_length, payload_char):
        """
        Sender function for LLC-based Covert Storage Channel via Packet Size Variation (CSC-PSV-LLC).

        :param log_file_name: File name to log the plain text message.
        :param threshold: The value that used to distinguish '0' vs. '1'.
        :param threshold_range: The range to add/subtract from the threshold to determine the payload size.
        :param llc_header_len: Length of the LLC header in bytes. (3 bytes in our case)
        :param frame_size_dot3: Frame size for Dot3 (Ethernet) in bytes. (60 bytes in our case)
        :param epsilon: A small value to avoid division by zero.
        :param min_payload_size: Minimum payload size to ensure a positive payload size.
        :param dst_mac: Destination MAC address for the LLC frames.
        :param delay_ms: Optional delay in milliseconds between consecutive packets.
        :param min_length: Minimum length of the random binary message.
        :param max_length: Maximum length of the random binary message.
        :param payload_char: Char value used to fill the payload.
        """
        # 1) Generate a random fixed-length message => 16 chars => 128 bits
        #    and log the generated plaintext into log_file_name.
        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name=log_file_name,
            min_length=min_length,
            max_length=max_length
        )
        # print(f"[Sender] Generated random binary message: {binary_message}")

        # print("[Sender] Starting LLC packet transmission ...")
        start_time = time.time()    # Start time for measuring transmission time

        # 2) Transmit one LLC packet per bit
        for idx, bit in enumerate(binary_message):
            # Decide payload size based on the bit value
            if bit == '1':
                payload_size = threshold + threshold_range
            else:
                payload_size = max(threshold - threshold_range, min_payload_size)  # Ensure payload_size is positive

            # Calculate Dot3 length: LLC headers (3 bytes) + Payload
            dot3_length = llc_header_len + payload_size

            # Ensure the total frame size meets the minimum Ethernet frame size (60 bytes for Dot3)
            if dot3_length < frame_size_dot3:
                padding = frame_size_dot3 - dot3_length
                payload = payload_char * payload_size + payload_char * padding
            else:
                payload = payload_char * payload_size

            # Build an LLC frame using Dot3 and LLC layers
            packet = (
                    Dot3(dst=dst_mac, src="02:42:ac:12:00:02", len=dot3_length) /
                    LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
                    Raw(load=payload)
            )

            # Debug print
            # print(f"[Sender DEBUG] bit={bit}, payload_size={payload_size}, packet #{idx + 1}")
            default_iface = scapy.config.conf.iface     # Get the default interface
            super().send(packet, interface=default_iface)

            # Optional small delay if needed to prevent packet loss
            if delay_ms > 0:
                time.sleep(delay_ms / 1000.0)

        end_time = time.time()  # End time for measuring transmission time
        elapsed = end_time - start_time # Calculate elapsed time
        if elapsed <= 0:
            elapsed = epsilon   # Avoid division by zero
        total_bits = len(binary_message)
        capacity_bps = total_bits / elapsed # Calculate the covert channel capacity in bps

        # print("[Sender] Finished sending LLC packets.")
        # print(f"[Sender] Total bits = {total_bits}, Elapsed = {elapsed:.4f} s")
        # print(f"[Sender] Covert Channel Capacity ~ {capacity_bps:.2f} bits/s")
        # print("Sender is finished!")

    def receive(self, threshold, log_file_name, byte_size, scapy_filter, stop_char):
        """
        Receiver function for LLC-based Covert Storage Channel via Packet Size Variation (CSC-PSV-LLC).

        :param threshold: Integer to distinguish '0' vs. '1'.
        :param log_file_name: File to log the decoded plaintext message.
        :param byte_size: Used to represent 8 bits in a byte.
        :param scapy_filter: Scapy filter to sniff LLC packets
        :param stop_char: Character to stop sniffing and decoding the message.
        """
        self.decoded_bits = ""
        self.decoded_message = ""
        self.stop_sniffing = False

        def parse_packet(pkt):
            if self.stop_sniffing:
                return

            # Ensure the packet has LLC layer and Raw payload
            if pkt.haslayer(LLC) and pkt.haslayer(Raw):
                payload_len = len(pkt[Raw].load)
                # print(f"[Receiver DEBUG] LLC packet detected, payload_len={payload_len}")

                # Decode bit based on payload size
                bit = '1' if payload_len > threshold else '0'
                self.decoded_bits += bit

                # For every 8 bits, convert to a character
                if len(self.decoded_bits) % byte_size == 0:
                    eight_bits = self.decoded_bits[-byte_size:]
                    char = self.convert_eight_bits_to_character(eight_bits)
                    self.decoded_message += char

                    # print(f"[Receiver DEBUG] Decoded 8 bits '{eight_bits}' => '{char}'")

                    # Stop sniffing if the stopping character is received
                    if char == stop_char:
                        self.stop_sniffing = True

        def stop_filter(_):
            return self.stop_sniffing

        # print("[Receiver] Starting to sniff on eth0 for LLC packets ...")
        default_iface = scapy.config.conf.iface
        # BPF filter for scapy sniff: "llc"
        sniff(
            iface=default_iface,
            filter=scapy_filter,
            prn=parse_packet,
            store=False,
            stop_filter=stop_filter
        )

        # print("[Receiver] Sniffing stopped.")
        final_message = self.decoded_message
        # print(f"[Receiver] Final decoded message = {final_message}")

        # Log the decoded message
        self.log_message(final_message, log_file_name)
        # print("Receiver is finished!")