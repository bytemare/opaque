package encoding

import (
	"testing"
)

func TestEncodeVectorLenPanic(t *testing.T) {
	/*
		EncodeVectorLen with size > 2
	*/
	defer func() {
		recover()
	}()

	EncodeVectorLen(nil, 3)
	t.Fatal("no panic with exceeding encoding length")
}
