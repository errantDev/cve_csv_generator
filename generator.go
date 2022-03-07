package cvecsvgenerator

import (
	"bufio"
	"os"
)

type CsvData interface {
	toString() string
}

type CveCsvData struct {
	CveId             string
	PublishedDate     string
	FirstReferenceUrl string
	Description       string
}

func (c *CveCsvData) toString() string {
	return "I am a csv full of cves"
}

func WriteData(w *bufio.Writer, data string) {
	f, _ := os.Create("./cves.csv")
	defer f.Close()
	w.WriteString(data)
	w.Flush()
}

func GetData() string {
	return "I am a csv full of cves"
}
