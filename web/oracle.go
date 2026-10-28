package web

func Oracle(send func(payload string) *Response, pred func(*Response) bool) func(string) (bool, error) {
	return func(payload string) (bool, error) {
		resp := send(payload)
		if resp == nil {
			return false, nil
		}
		return pred(resp), nil
	}
}

func GreaterOracle(send func(pos, value int) *Response, pred func(*Response) bool) func(pos, value int) (bool, error) {
	return func(pos, value int) (bool, error) {
		resp := send(pos, value)
		if resp == nil {
			return false, nil
		}
		return pred(resp), nil
	}
}
