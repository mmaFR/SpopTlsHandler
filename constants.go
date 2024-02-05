package SpopTlsHandler

import "crypto/elliptic"

const (
	RsaKeyType   string = "RSA"
	EcdsaKeyType string = "ECDSA"
	CurveP224    string = "P224"
	CurveP256    string = "P256"
	CurveP384    string = "P384"
	CurveP521    string = "P521"
)

const structure string = "tls_handler"

var curveMap map[string]elliptic.Curve = map[string]elliptic.Curve{
	CurveP224: elliptic.P224(),
	CurveP256: elliptic.P256(),
	CurveP384: elliptic.P384(),
	CurveP521: elliptic.P521(),
}
