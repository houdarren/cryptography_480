import time
import sys

secret_key = sys.argv[1]

length = len(secret_key) + 5

def naive_string_equals(test, actual):
    if len(test) == len(actual):
        for i in range(len(test)):
            if test[i] != actual[i]:
                return False
        return True
    return False

def build_string(length):
    return "x" * length

for i in range(length):
    total_time = 0
    for j in xrange(200000):
        test_string = build_string(i)
        start_time = time.clock() * 1000
        naive_string_equals(test_string, secret_key)
        end_time = time.clock() * 1000
        elapsed_time = int(end_time - start_time)  # time in milliseconds
        total_time += elapsed_time
    print(str(i) + ": " + str(total_time))



