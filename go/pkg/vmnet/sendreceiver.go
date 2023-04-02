package vmnet

// sendReceiver sends and receives whole messages atomically.
// This has the same shape as io.ReadWriter's Read and Write, but we use different functions
// to prevent confusion.
type sendReceiver interface {
	Send(packet []byte) (int, error)
	Recv(buffer []byte) (int, error)
}
