package output

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

type stageWriter struct{}

var (
	stageOutput stageWriter

	stageActive    bool
	stageLineStart = true
	stageBorder    int
)

func (stageWriter) Write(
	data []byte,
) (int, error) {
	if !stageActive {
		return os.Stdout.Write(data)
	}

	total := 0

	for len(data) > 0 {
		if stageLineStart {
			_, err := io.WriteString(
				os.Stdout,
				gray+"│ "+reset,
			)

			if err != nil {
				return total, err
			}

			stageLineStart = false
		}

		length := bytes.IndexByte(
			data,
			'\n',
		)

		if length < 0 {
			length = len(data)
		} else {
			length++
		}

		chunk := data[:length]

		n, err := os.Stdout.Write(chunk)

		total += n

		if err != nil {
			return total, err
		}

		if n != len(chunk) {
			return total, io.ErrShortWrite
		}

		if chunk[len(chunk)-1] == '\n' {
			stageLineStart = true
		}

		data = data[length:]
	}

	return total, nil
}

func beginStage(
	value string,
) {
	if stageActive {
		finishStage()
	}

	fmt.Println()
	fmt.Println(stage(value))

	stageBorder = stageWidth(value)
	stageActive = true
	stageLineStart = true
}

func finishStage() {
	if !stageActive {
		return
	}

	if !stageLineStart {
		fmt.Println()
	}

	fmt.Println(
		orange +
			"└" +
			strings.Repeat(
				"─",
				stageBorder,
			) +
			reset,
	)

	stageActive = false
	stageLineStart = true
}
