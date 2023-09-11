ja3_arr = []

extras = set()

ja3s = """0,5,10,11,13,16,18,21,23,27,35,43,45,51,17513,65281
0,5,10,11,13,16,18,21,23,27,35,43,45,51,17513,65281
0,5,10,11,13,16,18,21,23,27,35,43,45,51,17513,65281
0,5,10,11,13,16,18,21,23,27,35,43,45,51,17513,65281"""

for ja3 in ja3s.split("\n"):
    try:
        ja3 = ja3.split(",")
        if len(ja3_arr) == 0:
            ja3_arr = ja3
        else:
            for item in ja3_arr:
                if item not in ja3:
                    print("Not consistent", item)
                    ja3_arr.remove(item)
                else:
                    ja3.remove(item)
            extras.update(ja3)
    except EOFError:
        break


print(ja3_arr, len(ja3_arr))
print(extras, len(extras))
