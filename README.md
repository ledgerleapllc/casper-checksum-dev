## casper-checksum-dev

Test script for Validator ID checksum algorithm in python.

Create mixcased validator ID from all lowercase,
```
from CasperChecksum import Checksum as Checksum

reference_checksum = '011117189C666F81C5160CD610eE383dC9B2D0361F004934754D39752EeDc64957'
my_validator_id = reference_checksum.lower()

mixcase_validator_id = Checksum().do(my_validator_id)

print('result:     ', mixcase_validator_id)
print('reference:  ', reference_checksum)
print(mixcase_validator_id == reference_checksum)

```

Verify mixcased validator ID,
```
from CasperChecksum import Checksum as Checksum

correct_checksum = Checksum(mixcase_validator_id).do() # check checksum
print(correct_checksum)
```