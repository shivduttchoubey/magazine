# lora_config.py

class LoRaConfig:
    def __init__(self, spi, cs, reset, freq=868E6):
        from sx127x import SX127x
        self.lora = SX127x(spi, cs, reset, freq=freq)
        self.lora.set_mode_rx()
    
    def send(self, data):
        self.lora.send(bytes(data))
    
    def receive(self, timeout=10000):
        import utime
        start = utime.ticks_ms()
        while utime.ticks_diff(utime.ticks_ms(), start) < timeout:
            if self.lora.received_packet():
                return self.lora.read_payload()
        return None
