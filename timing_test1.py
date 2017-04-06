import time as timer
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
    time = 0
    for j in range(200000):
        test_string = build_string(i)
        start_time = timer.clock()
        naive_string_equals(test_string, secret_key)
        end_time = timer.clock()
        elapsed = end_time - start_time
        if elapsed > 0:
            time += elapsed 
    print(str(i) + ": " + str(time))



