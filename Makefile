all:
	CGO_ENABLED=0 go test ./... -v -count=1
	CGO_ENABLED=1 go test ./... -v -count=1
	CGO_ENABLED=1 go test . -tags=forceportable -v -count=1
	CGO_ENABLED=0 go test . -v -count=1 -run=NONE -bench=.
	CGO_ENABLED=1 go test . -v -count=1 -run=NONE -bench=.
	CGO_ENABLED=1 go test . -tags=forceportable -v -count=1 -run=NONE -bench=.

fmt:
	gofmt -w .

bench:
	CGO_ENABLED=1 go test . -run=NONE -bench=. -benchmem
	
check:
	CGO_ENABLED=1 go test ./... -v -count=1


