import cv2
img = cv2.imread('211119619784cbdb9fb.png')
YCrCb = cv2.cvtColor(img, cv2.COLOR_BGR2YCrCb)
R,G,B = cv2.split(YCrCb)
# lsb
cv2.imwrite('r.png', (R % 2) * 255)
cv2.imwrite('g.png', (G % 2) * 255)
cv2.imwrite('b.png', (B % 2) * 255)