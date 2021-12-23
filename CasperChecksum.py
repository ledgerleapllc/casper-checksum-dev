#!/usr/bin/env python

from blake2b import BLAKE2b as BLAKE2b

class Checksum():
	def __init__(self, vid = None):
		self.validator_id = None
		self.keytag = '01'
		self.algo = 'ed25519'

		if vid:
			self.validator_id = vid

		self.HEX_CHARS = [
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f',
			'A', 'B', 'C', 'D', 'E', 'F'
		]

		self.SMALL_BYTES_COUNT = 75

	def _blake_hash(self, public_key):
		blake = BLAKE2b(digest_size = 32)
		method = 2

		# try hash from ascii string, as per EIP-55 
		if method == 1:
			blake.update(
				bytes(public_key.hex(), 'utf-8')
			)


		# try hash from public key buffer
		elif method == 2:
			blake.update(public_key)


		# try hash according to the account-hash schema
		elif method == 3:
			blake.update(
				b''.join([
					bytes(self.algo, 'utf-8'),
					bytes.fromhex('00'),
					public_key
				])
			)

		# print(blake.hexdigest())
		# return blake.hexdigest()
		return blake.digest()

	def _bytes_to_nibbles(self, v):
		output_nibbles = []

		for b in v:
			output_nibbles.append(b >> 4)
			output_nibbles.append(b & 0x0f)

		return output_nibbles

	def _bytes_to_bits_cycle(self, v):
		_blake_hash = self._blake_hash(v)

		ret = []
		method = 6
		fill_bits = False

		# try taking binary string from entire hash
		if method == 1:
			bin_string = bin(int(_blake_hash.hex(), 16)).lstrip('0b')
			if fill_bits: bin_string = ('0' * (256 - len(bin_string))) + bin_string

			for i in range(0, len(bin_string)):
				ret.append(int(bin_string[i]))


		# try taking binary strings from nibbles
		elif method == 2:
			nibs = self._bytes_to_nibbles(_blake_hash)

			for i in range(0, len(nibs)):
				b = bin(nibs[i]).lstrip('0b')
				if fill_bits: b = ('0' * (4 - len(b))) + b

				for j in b:
					ret.append(int(j))


		# try taking binary strings from bytes
		elif method == 3:
			for byt in _blake_hash:
				b = bin(byt).lstrip('0b')
				if fill_bits: b = ('0' * (8 - len(b))) + b

				for j in b:
					ret.append(int(j))


		# try taking last bit in byte
		elif method == 4:
			for b in _blake_hash:
				ret.append(b % 2)
			for b in _blake_hash:
				ret.append(b % 2)
			for b in _blake_hash:
				ret.append(b % 2)
			for b in _blake_hash:
				ret.append(b % 2)


		# try taking last bit in nibble
		elif method == 5:
			nibs = self._bytes_to_nibbles(_blake_hash)

			for b in nibs:
				ret.append(b % 2)
			for b in nibs:
				ret.append(b % 2)

		elif method == 6:

			for b in _blake_hash:
				for j in range(8):
					ret.append((b>>j)&0x01)

		# print(ret)
		return ret

	def _encode(self, public_key):
		nibbles = self._bytes_to_nibbles(public_key)
		hash_bits = self._bytes_to_bits_cycle(public_key)
		ret = []

		k=0
		for nibble in nibbles:
			# print(hex(nibble), '    ', hash_bits[i])
			if nibble >= 10:
				if hash_bits[k] == 1:
					nibble += 6
				k+=1

			ret.append(self.HEX_CHARS[nibble])

		return ''.join(ret)

	def do(self, _v = None):
		if self.validator_id:
			self.keytag = self.validator_id[:2]
			self.validator_id = self.validator_id[2:]

			if self.keytag == '01':
				self.algo = 'ed25519'
			elif self.keytag == '02':
				self.algo = 'secp256k1'
			else:
				print('Invalid validator ID')
				exit(1)

			v = bytes.fromhex(self.validator_id)

			if len(v) > self.SMALL_BYTES_COUNT:
				return self.keytag + self.validator_id.lower()

			return self.keytag + self._encode(v)

		else:
			if not _v:
				return False

			self.keytag = _v[:2]
			_v = _v[2:]

			if self.keytag == '01':
				self.algo = 'ed25519'
			elif self.keytag == '02':
				self.algo = 'secp256k1'
			else:
				print('Invalid validator ID')
				exit(1)

			v = bytes.fromhex(_v)

			if len(v) > self.SMALL_BYTES_COUNT:
				return _v.lower()

			return self.keytag + self._encode(v)
