#!/usr/bin/env python

from CasperChecksum import Checksum as Checksum

if __name__ == '__main__':
	reference_checksum = '011117189C666F81C5160CD610eE383dC9B2D0361F004934754D39752EeDc64957'
	my_validator_id = reference_checksum.lower()
	# 011117189c666f81c5160cd610ee383dc9b2d0361f004934754d39752eedc64957

	mixcase_validator_id = Checksum().do(my_validator_id)

	print('result:     ', mixcase_validator_id)
	print('reference:  ', reference_checksum)
	print(mixcase_validator_id == reference_checksum)

	# correct_checksum = Checksum(mixcase_validator_id).do() # check checksum
	# print(correct_checksum)