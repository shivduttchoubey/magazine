MicroPython Scripts for Node A and Node B Using LoRa (ESP32)
Below are complete MicroPython scripts for both Node A and Node B, adapted from your original Python/WebSocket protocol to use LoRa for communication on ESP32. The logic, cryptography, and structure are preserved as closely as possible, with comments for clarity.

Note: You must have the following libraries (or equivalents) on your ESP32:

micropython-ecdsa (or a compatible ECDSA implementation)

ucryptolib or micropython-aes (for AES encryption)

micropython-hkdf (or implement HKDF)

A LoRa driver, e.g., uPyLoRa for SX127x modules