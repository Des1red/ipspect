package database

import (
	"embed"
	"io/fs"
)

//go:embed data/arp/*.csv
var arpFiles embed.FS

func OpenARP(
	name string,
) (fs.File, error) {
	return arpFiles.Open(
		"data/arp/" + name,
	)
}

//go:embed data/ports/services.csv
var portFiles embed.FS

func OpenPorts(
	name string,
) (fs.File, error) {
	return portFiles.Open(
		"data/ports/" + name,
	)
}

//go:embed data/recog/*.xml
var recogFiles embed.FS

func OpenRecog(name string) (fs.File, error) {
	return recogFiles.Open("data/recog/" + name)
}

//go:embed data/requests/*.yaml
var requestFiles embed.FS

func RequestFS() (fs.FS, error) {
	return fs.Sub(
		requestFiles,
		"data/requests",
	)
}
