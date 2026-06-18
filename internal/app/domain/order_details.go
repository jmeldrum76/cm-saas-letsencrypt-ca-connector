package domain

// OrderStatus represents the state of a certificate order/request.
type OrderStatus string

const (
	OrderStatusPending    OrderStatus = "PENDING"
	OrderStatusProcessing OrderStatus = "PROCESSING"
	OrderStatusCompleted  OrderStatus = "COMPLETED"
	OrderStatusFailed     OrderStatus = "FAILED"
)

// OrderDetails tracks the progress of an asynchronous certificate request.
// For this connector, ID carries the ACME order URL.
type OrderDetails struct {
	ID            string      `json:"id"`
	Status        OrderStatus `json:"status"`
	CertificateID string      `json:"certificateId"`
	ErrorMessage  string      `json:"errorMessage"`
}
