package cobenian

import (
	"fmt"
	"log"
)

type Person struct {
	FirstName string
	LastName  string
	Age       uint8
	polyglot  bool
}

func PersonToString(p *Person) (string, error) {
	if p == nil {
		return "", nil
	}
	s := fmt.Sprintf("person {first: %s, last: %s, age: %d}\n", p.FirstName, p.LastName, p.Age)
	fmt.Printf("serializing: %s\n", s)
	return s, nil
}

type PrintablePerson interface {
	String() string
}

func (p *Person) String() string {
	s, err := PersonToString(p)
	if err != nil {
		log.Fatal("Unable to print person with error %v\n", err)
	}
	return s
}
