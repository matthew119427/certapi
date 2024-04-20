package routes

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/gin-gonic/gin"
)

type PGPKey struct {
	FullName, Name, Comment, Email string
	CreationTime                   time.Time
	PublicKeyAlgorithm             packet.PublicKeyAlgorithm
	Fingerprint                    [20]byte
	KeyID                          uint64
}

func GetOpenPGPInformationEncoded(c *gin.Context) {
	query := c.Copy().Request.Body

	block, err := armor.Decode(query)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Unable to parse body.",
		})
		return
	}
	pkt := packet.NewReader(block.Body)
	entity, err := openpgp.ReadEntity(pkt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "Unable to parse body.",
		})
		return
	}
	if len(entity.Identities) > 1 {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  false,
			"message": "No identities found in PGP key.",
		})
		return
	}
	var key *PGPKey
	for name, identity := range entity.Identities {
		key = &PGPKey{
			FullName:           name,
			Name:               identity.UserId.Name,
			Comment:            identity.UserId.Comment,
			Email:              identity.UserId.Email,
			CreationTime:       entity.PrimaryKey.CreationTime,
			PublicKeyAlgorithm: entity.PrimaryKey.PubKeyAlgo,
			Fingerprint:        entity.PrimaryKey.Fingerprint,
			KeyID:              entity.PrimaryKey.KeyId,
		}
		break
	}

	// bitLength, _ := entity.PrimaryKey.BitLength()
	var bitLength int

	switch entity.PrimaryKey.PubKeyAlgo {
	case packet.PubKeyAlgoECDSA:
		if ecdsaKey, ok := entity.PrimaryKey.PublicKey.(*ecdsa.PublicKey); ok {
			bitLength = ecdsaKey.Params().BitSize
		} else {
			panic("expected ecdsa.PublicKey for type packet.PubKeyAlgoECDSA")
		}
	case packet.PubKeyAlgoRSA:
		if rsaKey, ok := entity.PrimaryKey.PublicKey.(*rsa.PublicKey); ok {
			bitLength = rsaKey.N.BitLen()
		} else {
			panic("expected rsa.PublicKey for type packet.PubKeyAlgoRSA")
		}
	default:
		val, _ := entity.PrimaryKey.BitLength()
		bitLength = int(val)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":             true,
		"fullName":           key.FullName,
		"name":               key.Name,
		"comment":            key.Comment,
		"email":              key.Email,
		"creationTime":       key.CreationTime,
		"publicKeyAlgorithm": key.PublicKeyAlgorithm,
		"fingerprint":        strings.ToUpper(hex.EncodeToString(key.Fingerprint[:])),
		"keyID":              entity.PrimaryKey.KeyIdString(),
		"bitLength":          bitLength,
	})
}
