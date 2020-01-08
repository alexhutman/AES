def transpose(matrix):
    return [[row[col] for row in matrix] for col in range(len(matrix[0]))]

def transpose_blocks(blocks):
    return [transpose(block) for block in blocks]
