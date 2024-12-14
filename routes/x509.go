package routes

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// GetCertificateInformationEncoded handler function for providing raw data to be parsed
func GetCertificateInformationEncoded(c *gin.Context) {
	query := c.Copy().Request.Body
	data, err := io.ReadAll(query)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Unable to parse body.",
		})
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Unable to decode PEM.",
		})
		return
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Unable to parse x509 data.",
		})
		return
	}

	var validationType string
	for _, value := range certificate.PolicyIdentifiers {
		if value.String() == "2.23.140.1.1" {
			validationType = "EV"
		} else if value.String() == "2.23.140.1.2.2" {
			validationType = "OV"
		} else if value.String() == "2.23.140.1.2.1" {
			validationType = "DV"
		}
	}

	var keyUsages []int
	var keyUsagesText []string
	var extendedKeyUsages []int
	var extendedKeyUsagesText []string
	for _, value := range certificate.ExtKeyUsage {
		switch value {
		case 0:
			// All Usages
			extendedKeyUsages = append(extendedKeyUsages, 0)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Any/All Usages")
			break
		case 1:
			// TLS Web Server Authentication
			extendedKeyUsages = append(extendedKeyUsages, 1)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "TLS Web Server Authentication")
			break
		case 2:
			// TLS Web Client Authentication
			extendedKeyUsages = append(extendedKeyUsages, 2)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "TLS Web Client Authentication")
			break
		case 3:
			// Code Signing
			extendedKeyUsages = append(extendedKeyUsages, 3)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Code Signing")
			break
		case 4:
			// Email Protection
			extendedKeyUsages = append(extendedKeyUsages, 4)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Email Protection (S/MIME)")
		default:
			break
		}
	}

	if certificate.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsages = append(keyUsages, 0)
		keyUsagesText = append(keyUsagesText, "CRL Signing")
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, 1)
		keyUsagesText = append(keyUsagesText, "Certificate Signing")
	}
	if certificate.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		keyUsages = append(keyUsages, 2)
		keyUsagesText = append(keyUsagesText, "Content Commitment")
	}
	if certificate.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsages = append(keyUsages, 3)
		keyUsagesText = append(keyUsagesText, "Data Encipherment")
	}
	if certificate.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		keyUsages = append(keyUsages, 4)
		keyUsagesText = append(keyUsagesText, "Decipher Only")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, 5)
		keyUsagesText = append(keyUsagesText, "Digital Signature")
	}
	if certificate.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		keyUsages = append(keyUsages, 6)
		keyUsagesText = append(keyUsagesText, "Encipher Only")
	}
	if certificate.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsages = append(keyUsages, 7)
		keyUsagesText = append(keyUsagesText, "Key Agreement")
	}
	if certificate.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, 8)
		keyUsagesText = append(keyUsagesText, "Key Encipherment")
	}

	sum := sha1.Sum(certificate.Raw)

	var bitLength int

	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
			bitLength = rsaKey.N.BitLen()
		} else {
			panic("expected rsa.PublicKey for type x509.RSA")
		}
	case x509.ECDSA:
		if ecdsaKey, ok := certificate.PublicKey.(*ecdsa.PublicKey); ok {
			bitLength = ecdsaKey.Params().BitSize
		} else {
			panic("expected ecdsa.PublicKey for type x509.ECDSA")
		}
	case x509.Ed25519:
		bitLength = ed25519.PublicKeySize
	default:
		panic("unhandled default case")
	}

	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"subject": gin.H{
			"commonName":         certificate.Subject.CommonName,
			"organization":       certificate.Subject.Organization,
			"organizationalUnit": certificate.Subject.OrganizationalUnit,
			"locality":           certificate.Subject.Locality,
			"country":            certificate.Subject.Country,
		},
		"issuer": gin.H{
			"commonName":         certificate.Issuer.CommonName,
			"organization":       certificate.Issuer.Organization,
			"organizationalUnit": certificate.Issuer.OrganizationalUnit,
			"locality":           certificate.Issuer.Locality,
			"country":            certificate.Issuer.Country,
		},
		"aia": gin.H{
			"issuingCertificateURL": certificate.IssuingCertificateURL,
			"ocspServer":            certificate.OCSPServer,
		},
		"validationType":         validationType,
		"signatureAlgorithm":     certificate.SignatureAlgorithm.String(),
		"publicKeyAlgorithm":     certificate.PublicKeyAlgorithm.String(),
		"serialNumber":           certificate.SerialNumber.String(),
		"notBefore":              certificate.NotBefore,
		"notAfter":               certificate.NotAfter,
		"keyUsage":               keyUsages,
		"keyUsageAsText":         keyUsagesText,
		"extendedKeyUsage":       extendedKeyUsages,
		"extendedKeyUsageAsText": extendedKeyUsagesText,
		"san":                    certificate.DNSNames,
		"emailAddresses":         certificate.EmailAddresses,
		"fingerprint":            strings.ToUpper(hex.EncodeToString(sum[:])),
		"bitLength":              bitLength,
		"pem":                    string(pem.EncodeToMemory(block)),
	})
}

// GetCertificateInfo handler
func GetCertificateInfo(c *gin.Context) {
	query := c.Query("q")
	resp, err := tls.Dial("tcp", query+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Could not establish connection with server.",
		})
		return
	}
	cipherSuite := tls.CipherSuiteName(resp.ConnectionState().CipherSuite)
	v := resp.ConnectionState().Version
	var tlsVersion string
	if v == tls.VersionSSL30 {
		tlsVersion = "SSLv3"
	} else if v == tls.VersionTLS10 {
		tlsVersion = "TLSv1"
	} else if v == tls.VersionTLS11 {
		tlsVersion = "TLSv1.1"
	} else if v == tls.VersionTLS12 {
		tlsVersion = "TLSv1.2"
	} else if v == tls.VersionTLS13 {
		tlsVersion = "TLSv1.3"
	} else {
		tlsVersion = "unknown"
	}
	certificate := resp.ConnectionState().PeerCertificates[0]
	rootCertificate := resp.ConnectionState().PeerCertificates[len(resp.ConnectionState().PeerCertificates)-1]

	var validationType string
	for _, value := range certificate.PolicyIdentifiers {
		if value.String() == "2.23.140.1.1" {
			validationType = "EV"
		} else if value.String() == "2.23.140.1.2.2" {
			validationType = "OV"
		} else if value.String() == "2.23.140.1.2.1" {
			validationType = "DV"
		}
	}

	var keyUsages []int
	var keyUsagesText []string
	var extendedKeyUsages []int
	var extendedKeyUsagesText []string
	for _, value := range certificate.ExtKeyUsage {
		switch value {
		case 0:
			// All Usages
			extendedKeyUsages = append(extendedKeyUsages, 0)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Any/All Usages")
			break
		case 1:
			// TLS Web Server Authentication
			extendedKeyUsages = append(extendedKeyUsages, 1)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "TLS Web Server Authentication")
			break
		case 2:
			// TLS Web Client Authentication
			extendedKeyUsages = append(extendedKeyUsages, 2)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "TLS Web Client Authentication")
			break
		case 3:
			// Code Signing
			extendedKeyUsages = append(extendedKeyUsages, 3)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Code Signing")
			break
		case 4:
			// Email Protection
			extendedKeyUsages = append(extendedKeyUsages, 4)
			extendedKeyUsagesText = append(extendedKeyUsagesText, "Email Protection (S/MIME)")
		default:
			break
		}
	}

	if certificate.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsages = append(keyUsages, 0)
		keyUsagesText = append(keyUsagesText, "CRL Signing")
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, 1)
		keyUsagesText = append(keyUsagesText, "Certificate Signing")
	}
	if certificate.KeyUsage&x509.KeyUsageContentCommitment != 0 {
		keyUsages = append(keyUsages, 2)
		keyUsagesText = append(keyUsagesText, "Content Commitment")
	}
	if certificate.KeyUsage&x509.KeyUsageDataEncipherment != 0 {
		keyUsages = append(keyUsages, 3)
		keyUsagesText = append(keyUsagesText, "Data Encipherment")
	}
	if certificate.KeyUsage&x509.KeyUsageDecipherOnly != 0 {
		keyUsages = append(keyUsages, 4)
		keyUsagesText = append(keyUsagesText, "Decipher Only")
	}
	if certificate.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, 5)
		keyUsagesText = append(keyUsagesText, "Digital Signature")
	}
	if certificate.KeyUsage&x509.KeyUsageEncipherOnly != 0 {
		keyUsages = append(keyUsages, 6)
		keyUsagesText = append(keyUsagesText, "Encipher Only")
	}
	if certificate.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		keyUsages = append(keyUsages, 7)
		keyUsagesText = append(keyUsagesText, "Key Agreement")
	}
	if certificate.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, 8)
		keyUsagesText = append(keyUsagesText, "Key Encipherment")
	}

	sum := sha1.Sum(certificate.Raw)

	var bitLength int

	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
			bitLength = rsaKey.N.BitLen()
		} else {
			panic("expected rsa.PublicKey for type x509.RSA")
		}
	case x509.ECDSA:
		if ecdsaKey, ok := certificate.PublicKey.(*ecdsa.PublicKey); ok {
			bitLength = ecdsaKey.Params().BitSize
		} else {
			panic("expected ecdsa.PublicKey for type x509.ECDSA")
		}
	default:
		// undefined behavior
		panic("unhandled default case")
	}

	c.JSON(http.StatusOK, gin.H{
		"status": true,
		"subject": gin.H{
			"commonName":         certificate.Subject.CommonName,
			"organization":       certificate.Subject.Organization,
			"organizationalUnit": certificate.Subject.OrganizationalUnit,
			"locality":           certificate.Subject.Locality,
			"province":           certificate.Subject.Province,
			"country":            certificate.Subject.Country,
		},
		"issuer": gin.H{
			"commonName":         certificate.Issuer.CommonName,
			"organization":       certificate.Issuer.Organization,
			"organizationalUnit": certificate.Issuer.OrganizationalUnit,
			"locality":           certificate.Issuer.Locality,
			"province":           certificate.Issuer.Province,
			"country":            certificate.Issuer.Country,
		},
		"root": gin.H{
			"commonName":         rootCertificate.Issuer.CommonName,
			"organization":       rootCertificate.Issuer.Organization,
			"organizationalUnit": rootCertificate.Issuer.OrganizationalUnit,
			"locality":           rootCertificate.Issuer.Locality,
			"country":            rootCertificate.Issuer.Country,
		},
		"aia": gin.H{
			"issuingCertificateURL": certificate.IssuingCertificateURL,
			"ocspServer":            certificate.OCSPServer,
		},
		"validationType":         validationType,
		"signatureAlgorithm":     certificate.SignatureAlgorithm.String(),
		"publicKeyAlgorithm":     certificate.PublicKeyAlgorithm.String(),
		"serialNumber":           certificate.SerialNumber.String(),
		"notBefore":              certificate.NotBefore,
		"notAfter":               certificate.NotAfter,
		"keyUsage":               keyUsages,
		"keyUsageAsText":         keyUsagesText,
		"extendedKeyUsage":       extendedKeyUsages,
		"extendedKeyUsageAsText": extendedKeyUsagesText,
		"san":                    certificate.DNSNames,
		"emailAddresses":         certificate.EmailAddresses,
		"fingerprint":            hex.EncodeToString(sum[:]),
		"bitLength":              bitLength,
		"connection": gin.H{
			"tlsVersion":  tlsVersion,
			"cipherSuite": cipherSuite,
		},
	})
}
