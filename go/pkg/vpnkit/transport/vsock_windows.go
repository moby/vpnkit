package transport

func NewVsockTransport() Transport {
	return &hvs{}
}
