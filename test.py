import sniffer

# Run this file!
# Edit count to 0 if you want infinite run time, or to any amount to sniff that many packets
#packet_sniffer = sniffer.PacketSniffer(count=0, duration=10, packet_logging = True, terminal_logging=False)
#packet_sniffer.start()

class MyClass:
    def __init__(self):
        self.attribute1 = "value1"
        self.method1 = self._my_method
        self.attribute2 = None
        
    def _my_method(self):
        pass

obj = MyClass()

print(hasattr(obj, 'attribute1'))  # Output: True
print(hasattr(obj, 'method1'))     # Output: True
print(hasattr(obj, 'attribute2')) # Output: False