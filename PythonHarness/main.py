from argon2 import PasswordHasher, Type
import sys

memory_cost = int(sys.argv[1])
parallelism = int(sys.argv[2])
iterations = int(sys.argv[3])
hash_len = int(sys.argv[4])
hashValue = sys.argv[5]
password = sys.argv[6]

ph = PasswordHasher(
    memory_cost=memory_cost,
    time_cost=iterations,
    parallelism=parallelism,
    hash_len=hash_len,
    type=Type.ID,
)

print(
    f'Evaluating hash with the following params: mem:{memory_cost}, parallelism {parallelism}, iterations {iterations}, hashLen {hash_len}, pass {password}')

# hv = ph.hash(password)
# print(hv)

try:
    isValid = ph.verify(hashValue, password)
except Exception as ex:
    print(repr(ex))
    print(False)
    sys.exit(1)


print(isValid)
sys.exit(int(not isValid))
