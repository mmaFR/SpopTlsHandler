package SpopTlsHandler

import (
	"crypto/x509"
	"fmt"
	"github.com/mmaFR/CryptoUtils"

	"errors"
	"time"
)

func GenerateCertificate(args arguments) {
	const function string = "generateCertificate"
	var err error

	switch {
	case args.GetGenCa() && !args.GetGenSpoaCert() && !args.GetGenSpoeCert():
		Logger.LogEmerge(structure, function, "Generating a CA certificate", -1)
		Logger.LogEmerge(structure, function, "Using key of type %s", -1, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.LogEmerge(structure, function, "Using a key size of %d bits", -1, args.GetKeySize())
		case EcdsaKeyType:
			Logger.LogEmerge(structure, function, "Using the key curve %s", -1, args.GetKeyCurve())

		}
		if err = genCa(args); err != nil {
			Logger.LogError(structure, function, "Error encountered while generating the CA certificate: %s", -1, err.Error())
		} else {
			Logger.LogEmerge(structure, function, "CA certificate and key saved in %s", -1, args.GetCertOut())
		}
		return
	case args.GetGenSpoeCert() && !args.GetGenCa() && !args.GetGenSpoaCert():
		Logger.LogEmerge(structure, function, "Generating an SPOE (HAProxy side) certificate", -1)
		Logger.LogEmerge(structure, function, "Using key of type %s", -1, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.LogEmerge(structure, function, "Using a key size of %d bits", -1, args.GetKeySize())
		case EcdsaKeyType:
			Logger.LogEmerge(structure, function, "Using the key curve %s", -1, args.GetKeyCurve())

		}
		if err = genSpoeCert(args); err != nil {
			Logger.LogError(structure, function, "Error encountered while generating the SPOE certificate: %s", -1, err.Error())
		} else {
			Logger.LogEmerge(structure, function, "SPOE certificate and key saved in %s", -1, args.GetCertOut())
		}
		return
	case args.GetGenSpoaCert() && !args.GetGenCa() && !args.GetGenSpoeCert():
		Logger.LogEmerge(structure, function, "Generating an SPOA (HAProxy side) certificate", -1)
		Logger.LogEmerge(structure, function, "Using key of type %s", -1, args.GetKeyType())
		switch args.GetKeyType() {
		case RsaKeyType:
			Logger.LogEmerge(structure, function, "Using a key size of %d bits", -1, args.GetKeySize())
		case EcdsaKeyType:
			Logger.LogEmerge(structure, function, "Using the key curve %s", -1, args.GetKeyCurve())

		}
		if err = genSpoaCert(args); err != nil {
			Logger.LogError(structure, function, "Error encountered while generating the SPOA certificate: %s", -1, err.Error())
		} else {
			Logger.LogEmerge(structure, function, "SPOA certificate and key saved in %s", -1, args.GetCertOut())
		}
		return
	case args.GetGenCa(), args.GetGenSpoaCert(), args.GetGenSpoeCert():
		fmt.Println("you can't mix GenCa, GenSpoe, and GenSpoa")
		return
	}
}

func genCa(args arguments) error {
	var err error
	var certDesc *CryptoUtils.CertificateDescription
	var pki *CryptoUtils.Pki = CryptoUtils.NewPki()

	if args.GetCn() == "" {
		return errors.New("please provide a common name with -cn")
	}

	switch args.GetKeyType() {
	case RsaKeyType:
		if err = pki.GenerateCaRsaKeys(int(args.GetKeySize())); err != nil {
			return err
		}
	case EcdsaKeyType:
		if err = pki.GenerateCaEcdsaKeys(curveMap[args.GetKeyCurve()]); err != nil {
			return err
		}
	}

	certDesc = CryptoUtils.NewCertificateDescription()
	certDesc.SetIsCA()
	certDesc.SetCommonName(args.GetCn())
	certDesc.SetOrganization("HAProxy Agent")
	certDesc.SetOrganizationalUnit("SPOA")
	certDesc.SetCountry("FR")
	certDesc.SetProvince("IDF")
	certDesc.SetLocality("Paris")
	certDesc.SetStreetAddress("")
	certDesc.SetPostalCode("75000")
	certDesc.SetNotValidBefore(time.Now())
	certDesc.SetNotValidAfter(time.Now().Add(time.Hour * 24 * 365 * 10))

	if err = pki.GenerateCaCert(certDesc); err != nil {
		return err
	}
	var crt []byte
	if crt, err = pki.ExportCa(CryptoUtils.FormatPEM); err != nil {
		return err
	}

	if err = dumpBytesToFile(args.GetCertOut(), crt); err != nil {
		return err
	}
	return nil
}
func genSpoeCert(args arguments) error {
	return genCert(args, true)
}
func genSpoaCert(args arguments) error {
	return genCert(args, false)
}
func genCert(args arguments, isClient bool) error {
	var err error
	var certDesc *CryptoUtils.CertificateDescription
	var pki *CryptoUtils.Pki = CryptoUtils.NewPki()
	var caCertBytes []byte
	var crt []byte

	if args.GetCn() == "" {
		return errors.New("please provide a common name with -cn")
	}

	if caCertBytes, err = loadBytesFromFile(args.GetCaCert()); err != nil {
		return err
	}

	if err = pki.InitCaFromPem(caCertBytes); err != nil {
		return err
	}

	switch args.GetKeyType() {
	case RsaKeyType:
		if err = pki.GenerateCertRsaKeys(int(args.GetKeySize())); err != nil {
			return err
		}
	case EcdsaKeyType:
		if err = pki.GenerateCertEcdsaKeys(curveMap[args.GetKeyCurve()]); err != nil {
			return err
		}
	}

	certDesc = CryptoUtils.NewCertificateDescription()
	certDesc.SetCommonName(args.GetCn())
	certDesc.SetOrganization("HAProxy Agent")
	certDesc.SetOrganizationalUnit("SPOA")
	certDesc.SetCountry("FR")
	certDesc.SetProvince("IDF")
	certDesc.SetLocality("Paris")
	certDesc.SetStreetAddress("")
	certDesc.SetPostalCode("75000")
	certDesc.SetNotValidBefore(time.Now())
	certDesc.SetNotValidAfter(time.Now().Add(time.Hour * 24 * 365 * 10))
	if isClient {
		certDesc.SetExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	} else {
		certDesc.SetExtKeyUsage([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	}

	if err = pki.GenerateCert(certDesc); err != nil {
		return err
	}

	if crt, err = pki.ExportCert(CryptoUtils.FormatPEM); err != nil {
		return err
	}

	if err = dumpBytesToFile(args.GetCertOut(), crt); err != nil {
		return err
	}
	return nil
}
