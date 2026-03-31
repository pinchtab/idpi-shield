module integration-tests

go 1.23.0

require github.com/pinchtab/idpishield v0.0.0

require (
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)

replace github.com/pinchtab/idpishield => ../..
