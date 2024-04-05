class Blockchain:
    def __init__(self):
        self.blocks = []

    def to_dict(self):
        return {"blocks": [block.to_dict() for block in self.blocks]}

    def add_block_to_chain(self, block):
        self.blocks.append(block)
