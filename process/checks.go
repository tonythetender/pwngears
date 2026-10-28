package process

import "time"

type Check func(Tube) bool

func RecvLineContains(substr string) Check {
	return func(t Tube) bool {
		line, err := t.RecvLine()
		if err != nil {
			return false
		}
		return Contains(line, substr)
	}
}

func RecvContains(substr string) Check {
	return func(t Tube) bool {
		data, _ := t.RecvAll(300 * time.Millisecond)
		return Contains(data, substr)
	}
}

func Survives() Check {
	return func(t Tube) bool {
		_, err := t.RecvLine()
		return err == nil
	}
}

func Crashed() Check {
	return func(t Tube) bool {
		_, err := t.RecvLine()
		return err != nil
	}
}
