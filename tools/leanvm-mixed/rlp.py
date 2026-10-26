"""Development-only decoder for archived Optimism fixture payloads."""
def decode(data):
    def item(at):
        tag = data[at]; at += 1
        if tag < 128: return bytes([tag]), at
        is_list = tag >= 192
        base = 192 if is_list else 128
        length = tag - base
        if length > 55:
            n = length - 55
            length = int.from_bytes(data[at:at+n], 'big'); at += n
        end = at + length
        if end > len(data): raise ValueError('truncated RLP')
        if not is_list: return data[at:end], end
        result = []
        while at < end:
            value, at = item(at); result.append(value)
        if at != end: raise ValueError('RLP list boundary')
        return result, end
    value, end = item(0)
    if end != len(data): raise ValueError('trailing RLP')
    return value
