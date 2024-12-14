package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/matthew119427/certapi/routes"
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
	err := router.Run()
	if err != nil {
		panic("Router unable to initialize.")
	}
}
