package main

import (
  "fmt"
)

func doSomething(s string) {
  fmt.Println(s)
}

func main() {
  go doSomething("a")
  go doSomething("b")
}
