import sys
import string

def asciize(word):
    """remove special characters"""
    asciize = str.maketrans("àäâąãảạầằẩắéèëêệěēếėęìïîḯĩıịĭỉòöôõōơộốőơờúùüûūůủüưýỹÿỳğçłśșňñľđḑḏðẕźżḩḥẖťṭț",
                            "aaaaaaaaaaaeeeeeeeeeeiiiiiiiiiooooooooooouuuuuuuuuyyyygclssnnlddddzzzhhhttt")
    asciize2 = str.maketrans({"œ":"oe", "ß":"ss", "æ":"ae"})
    word = word.translate(asciize).translate(asciize2)
    res = ''
    for l in word:
        if l in string.printable:
            res += l
    return res

with open(sys.argv[1]) as wl:
    res = set()
    for line in wl.readlines():
        res.add(asciize(line.lower()))
    f = open(sys.argv[1]+"_asciized","w")
    f.write(''.join(list(res)))

print("done")
