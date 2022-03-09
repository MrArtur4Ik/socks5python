def get_byte(i: int):
	return i.to_bytes(1, "big")

def get_int_from_bytes(b: bytes):
	return int.from_bytes(b, "big")