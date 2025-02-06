# flow/Flow.py

class Flow:
    def __init__(self, packet):
        self.packet = packet
        # Initialize other attributes as needed

    def new(self, packet, direction):
        # Update the flow with a new packet
        pass

    def terminated(self):
        # Handle flow termination
        pass

    def getFlowLastSeen(self):
        # Return the timestamp of the last seen packet in the flow
        pass