fmt:
	gofmt -w .

bench:
	CGO_ENABLED=0 go test . -run=NONE -bench=. -benchmem
	#CGO_ENABLED=1 go test . -run=NONE -bench=. -benchmem
