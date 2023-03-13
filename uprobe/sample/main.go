package main

import "fmt"

//go:noinline
func Uprobe(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q int) (x, y int) {
	x = a + b + c + d
	y = e + f + g
	return
}

func main() {
	h, i := Uprobe(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17)
	fmt.Println(h, i)
}
