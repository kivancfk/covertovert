## Covert Storage Channel that exploits Packet Size Variation using LLC [Code: CSC-PSV-LLC]

---
**Authors**: Alp Doğan ARSLAN, Kıvanç FİLİZCİ

**Repository Link**:  https://github.com/kivancfk/covertovert 

---

### **Table of Contents**
1. [Programming Assignment (PA) Overview](#1-programming-assignment-pa-overview)
2. [Implementation Details](#2-implementation-details)
3. [Parameter Constraints and Limitations](#3-parameter-constraints-and-limitations)
4. [Covert Channel Capacity Measurement](#4-covert-channel-capacity-measurement)
5. [Usage Instructions](#5-usage-instructions)



### **1. Programming Assignment (PA) Overview**

This PA is conducted as the second phase of programming assignment for the course **CENG-435: Data Communication and Networking** in Fall 2024 at **METU**.

The goal of this PA is to implement a **Covert Storage Channel** using **Packet Size Variation (PSV)** and **Logical Link Control (LLC)**. 

-  **Covert Storage Channel (CSC)** is a method used to secretly transfer information by embedding data into existing network structures. Unlike traditional communication channels, covert channels bypass standard security controls, making detection and prevention challenging.
In this method, the sender manipulates payload sizes to encode binary data ('0' and '1'), and the receiver decodes the information based on observed packet sizes. Common Techniques for CSC:

      - Protocol Field Manipulation: Embeds data into protocol headers like TCP sequence numbers or IP identification fields.

      - Packet Bursting: Encodes information by varying the number of packets sent in bursts.

      - Packet Size Variation (PSV): Adjusts the size of packets to represent binary values (used in this project).

- **Packet Size Variation (PSV)** is a covert storage channel technique where binary data is encoded by modifying the size of packets. It leverages packet payload length as the carrier of information. Packet size variations are common in legitimate traffic, making it difficult to detect covert data.
An example of PSV rule:

       '1' Bit: Larger packet size (greater than a threshold).

       '0' Bit: Smaller packet size (less than or equal to a threshold).

**Logical Link Control (LLC)** is a sublayer of the Data Link Layer in the OSI model. It controls logical communication between devices over a network. LLC frames consist of a header and a payload. In this project, we use LLC frames to encode binary data based on payload sizes.

### **2. Implementation Details**

#### **Encoding Rule:**
- Encoding is conducted in sender side. We determined a threshold value (60 bytes) to distinguish the binary data, '0' vs '1' as shown below:
  - **'1' Bit** if payload length > threshold
  - **'0' Bit** if payload length <= threshold

#### **Protocol Layers:**
- **Dot3 (IEEE 802.3 Ethernet Frames):** Used to create LLC-based frames.
- **LLC (Logical Link Control):** Controls logical communication.
- **Raw Layer:** Encodes variable payload sizes.

#### **Communication Flow:**
1. **Sender**:
   - Generates a random binary message (16 characters = 128 bits in our PA).
   - Sends packets with different payload sizes based on the message bits.
2. **Receiver**:
   - Sniffs LLC frames to observe payload sizes.
   - Decodes binary bits based on payload length.
   - Reconstructs the original message.

### **3. Parameter Constraints and Limitations**
1. **Sender**
    ```python
        send(self, log_file_name, threshold, threshold_range, llc_header_len, frame_size_dot3,
             epsilon, min_payload_size, dst_mac, delay_ms, min_length, max_length, payload_char)
    ```
    - **log_file_name**     : File name to log the encoded plaint text message.
    - **threshold**         : The value that used to distinguish '0' vs. '1'. (60 bytes in our case)
    - **threshold_range**   : The range to add/subtract from the threshold to determine the payload size.
    - **llc_header_len**    : Length of the LLC header in bytes. (3 bytes in our case)
    - **frame_size_dot3**   : FLLC frames are padded to meet the Ethernet minimum size of 60 bytes. (60 bytes in our case)
    - **epsilon**           : A small value to avoid division by zero. (0.0001 in our case)
    - **min_payload_size**  : Minimum payload size to ensure a positive payload size. (1 byte in our case)
    - **dst_mac**           : Destination MAC address for the LLC frames. (ff:ff:ff:ff:ff:ff in our case)
    - **delay_ms**          : Optional delay in milliseconds between consecutive packets. (0 ms in our case)
    - **min_length**        : Minimum length of the random binary message. (16 bytes in our case)
    - **max_length**        : Maximum length of the random binary message. (16 bytes in our case)
    - **payload_char**      : Char value used to fill the payload. ('X' in our case)


2. **Receiver**
    ```python
        receive(self, threshold, log_file_name, byte_size, scapy_filter, stop_char)
    ```
   
    - **threshold**         : Integer to distinguish '0' vs. '1'. (60 bytes in our case)
    - **log_file_name**     : File to log the decoded plain text message. 
    - **byte_size**         : Used to represent 8 bits in a byte. (8 bits in our case)
    - **scapy_filter**      : Scapy filter to sniff LLC packets based on the destination MAC address. ("llc" in our case)
    - **stop_char**         : Character to stop sniffing and decoding the message. ('.' in our case)

### **4. Covert Channel Capacity Measurement**

#### Steps to calculate the covert channel capacity ####

- Create a **binary message** whose length is 128 bits.
- Start the **timer** just before sending the first packet.
  ```python
     start_time = time.time() 
  ```
- Finish the **timer**, just after sending the last packet.
  ```python
     end_time = time.time()  
  ```

- Find the difference in seconds.
  ```python
     elapsed = end_time - start_time  
     if elapsed <= 0:
        elapsed = epsilon   # Avoid division by zero (epsilon = 0.0001)
  ```
  
- Divide 128 by the calculated time in seconds.
  ```python
     total_bits = len(binary_message)    # 128 bits in our PA
     capacity_bps = total_bits / elapsed # Calculate the covert channel capacity in bps
  ```
- 

#### The Covert Channel Capacity in our PA ####
* The Covert Channel Capacity ~ 70 bits/s

### **5. Usage Instructions**

#### **1. Run the Receiver**:
```bash
make receive
```

#### **2. Run the Sender**:
```bash
make send
```

#### **3. Compare Sent and Received Logs**:
```bash
make compare
```
