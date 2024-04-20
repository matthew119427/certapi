package main

import (
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"gitlab.libraryofcode.org/engineering/certificate-api/routes"
)

func main() {
	router := gin.Default()

	router.GET("/", routes.GetCertificateInfo)
	router.GET("/tls", routes.GetCertificateInfo)
	router.POST("/parse", routes.GetCertificateInformationEncoded)
	router.POST("/pgp", routes.GetOpenPGPInformationEncoded)
	
	
	// router.POST("/encoding/pgp/armor-binary", routes.PGPArmorToBinary)
	// router.POST("/encoding/x509/pem-der", routes.X509PEMToDER)
	// router.POST("/encoding/x509/der-pem", routes.X509DERtoPEM)

	router.Use(cors.Default())
	router.Run()
}
