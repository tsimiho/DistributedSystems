class Blockchain:
    def __init__(self):
        self.blocks = []

    def add_block_to_chain(self, block):
        self.blocks.append(block)
