package main

import "encoding/json"

func jsonUnmarshal(data []byte, dst any) error {
	return json.Unmarshal(data, dst)
}
