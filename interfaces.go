package SpopTlsHandler

type arguments interface {
	GetBindAddressAndPort() string
	GetKeyType() string
	GetKeySize() uint16
	GetKeyCurve() string
	GetCertOut() string
	GetCn() string
	GetSpoaCert() string
	GetCaCert() string
	GetGenCa() bool
	GetGenSpoeCert() bool
	GetGenSpoaCert() bool
}

type logger interface {
	LogEmerge(structure, function, msg string, id int, vars ...any)
	LogAlert(structure, function, msg string, id int, vars ...any)
	LogCritical(structure, function, msg string, id int, vars ...any)
	LogError(structure, function, msg string, id int, vars ...any)
	LogWarning(structure, function, msg string, id int, vars ...any)
	LogNotice(structure, function, msg string, id int, vars ...any)
	LogInfo(structure, function, msg string, id int, vars ...any)
	LogDebug(structure, function, msg string, id int, vars ...any)
	LogTrace(structure, function, msg string, id int, vars ...any)
	FatalEmerge(structure, function, msg string, id int, vars ...any)
	FatalAlert(structure, function, msg string, id int, vars ...any)
	FatalCritical(structure, function, msg string, id int, vars ...any)
	FatalError(structure, function, msg string, id int, vars ...any)
	FatalWarning(structure, function, msg string, id int, vars ...any)
	FatalNotice(structure, function, msg string, id int, vars ...any)
	FatalInfo(structure, function, msg string, id int, vars ...any)
	FatalDebug(structure, function, msg string, id int, vars ...any)
	FatalTrace(structure, function, msg string, id int, vars ...any)
}
