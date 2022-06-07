package utils

func Yield(cell func(_channel chan interface{})) chan interface{} {
	channel := make(chan interface{})
	go func() {
		cell(channel)
		close(channel)
	}()
	return channel
}
