from PIL import Image

im = Image.open("image.jpg")
print(im.format, im.size, im.mode)

width = im.size[0]
height = im.size[1]

startX = 9
startY = 14

spacingX = 19
spacingY = 28

""""
# blue = 224 = C
# red = 228 = T
# yellow = 103 = G
# green = 2 = A
"""


# T
def blue(r, g, b):
	return abs(r - 5) < 15 and abs(g - 161) < 15 and abs(b - 225) < 15


# T
def red(r, g, b):
	return abs(r - 237) < 15 and abs(g - 28) < 15 and abs(b - 34) < 15


# A
def green(r, g, b):
	return abs(r - 35) < 15 and abs(g - 178) < 15 and abs(b - 73) < 15


# C
def yellow(r, g, b):
	return abs(r - 254) < 15 and abs(g - 240) < 15 and abs(b - 11) < 15


sol = ""
y = startY
while y < height:
	x = startX
	while x < width:
		r, g, b = im.getpixel((x, y))
		print(r, g, b)

		if blue(r, g, b):
			sol += "C"
		if red(r, g, b):
			sol += "U"
		if green(r, g, b):
			sol += "A"
		if yellow(r, g, b):
			sol += "G"

		x += spacingX
	y += spacingY

print(sol)