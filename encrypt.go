package main

import (
   "fmt"
   "net/http"
  
   "crypto/rand"
   "crypto/rsa"
   "crypto/x509"
   "encoding/pem"

   "github.com/hyperledger/fabric/core/chaincode/shim"
   "github.com/hyperledger/fabric/protos/peer"
)

//=================================================================================================
//================================================================================= RETURN HANDLING

// Success HTTP 2xx with a payload
func Success(rc int32, doc string, payload []byte) peer.Response {
	return peer.Response{
		Status:  rc,
		Message: doc,
		Payload: payload,
	}
}

// Error HTTP 4xx or 5xx with an error message
func Error(rc int32, doc string) peer.Response {
	logger.Errorf("Error %d = %s", rc, doc)
	return peer.Response{
		Status:  rc,
		Message: doc,
	}
}

//=================================================================================================
//======================================================================================= MAIN/INIT
var logger = shim.NewLogger("chaincode")

type SmartContract struct {
}

func main() {
	if err := shim.Start(new(SmartContract)); err != nil {
		fmt.Printf("Main: Error starting chaincode: %s", err)
	}
	logger.SetLevel(shim.LogDebug)
}

// Init is called during Instantiate transaction.
func (cc *SmartContract) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return Success(http.StatusNoContent, "OK", nil)
}

const DECKEY = "DECKEY"
const ENCKEY = "ENCKEY"
const KEY = "key"
const VALUE = "value"

// Invoke is called to update or query the ledger in a proposal transaction.
func (cc *SmartContract) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
   // get arguments and transient
   f, _ := stub.GetFunctionAndParameters()
   // for the arguments correlated to encryption,
   // they are supposed to be store in transient map instead of arguments array.
   // please remind that data in argument array persist in the ledger.
   tMap, err := stub.GetTransient()
   if err != nil {
      return shim.Error(fmt.Sprintf("Could not retrieve transient, err %s", err))
   }

   switch f {

     case "ENCRYPT":
        // make sure there's a key in transient - the assumption is that
        // it's associated to the string "ENCKEY"
        if _, in := tMap[ENCKEY]; !in {
           return shim.Error(fmt.Sprintf("Expected transient encryption key %s", ENCKEY))
        }

	encKey := string(tMap[ENCKEY])

        if _, ok := tMap[KEY]; !ok {
           return Error(http.StatusBadRequest, "Cannot find state key")
        }
        if _, ok := tMap[VALUE]; !ok {
   	   return Error(http.StatusBadRequest, "Cannot find state value")
        }

	args := []string{string(tMap[KEY]), string(tMap[VALUE])}

	return cc.RsaEncrypt(stub, args[0:], encKey)

      case "DECRYPT":
        // make sure there's a key in transient - the assumption is that
        // it's associated to the string "DECKEY"
        if _, in := tMap[DECKEY]; !in {
           return shim.Error(fmt.Sprintf("Expected transient decryption key %s", DECKEY))
        }
	decKey := string(tMap[DECKEY])

        if _, ok := tMap[KEY]; !ok {
	   return Error(http.StatusBadRequest, "Cannot find state key")
        }

        args := []string{string(tMap[KEY])}

        return cc.RsaDecrypt(stub, args[0:], decKey)

     default:
	return Error(http.StatusNotImplemented, "Invalid method! Valid methods are 'decrypt|encrypt'!")
   }
}

func (s *SmartContract) RsaEncrypt(stub shim.ChaincodeStubInterface, args []string, PublicKey string) peer.Response {
   if len(args) != 2 {
       return Error(http.StatusBadRequest, "Expected 2 parameters to function Encrypt")
   }

   key := args[0] //is ID not actual Key
   value := args[1] //String to encrypt

   block, _ := pem.Decode([]byte(PublicKey))
   if block == nil {
      return Error(http.StatusInternalServerError, "Invalid public key data")
   }
   if block.Type != "PUBLIC KEY" {
	return Error(http.StatusInternalServerError, "Invalid public key type")
    }

   pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
   if err != nil {
       return Error(http.StatusInternalServerError, err.Error())
   }

   pub, ok := pubInterface.(*rsa.PublicKey)
    if !ok {
	return Error(http.StatusInternalServerError, "Not RSA public key")
    }
  
   ent, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(value))
   if err != nil {
      return Error(http.StatusInternalServerError, err.Error())
   }

   if err := stub.PutState(key, ent); err == nil {
      return Success(http.StatusCreated, "Created", nil)
   } else {
      return Error(http.StatusInternalServerError, err.Error())
   }
}

func (s *SmartContract) RsaDecrypt(stub shim.ChaincodeStubInterface, args []string, PrivateKey string) peer.Response {
   if len(args) != 1 {
      return Error(http.StatusBadRequest, "Expected 1 parameters to function Decrypt")
   }

   key := args[0] //is ID not actual Key

   block, _ := pem.Decode([]byte(PrivateKey))
   if block == nil {
      return Error(http.StatusInternalServerError, "Invalid private key data")
   }

   var privInterface *rsa.PrivateKey
   var err1 error
   if block.Type == "RSA PRIVATE KEY" {
      privInterface, err1 = x509.ParsePKCS1PrivateKey(block.Bytes)
      if err1 != nil {
         return Error(http.StatusInternalServerError, err1.Error())
      }
   } else if block.Type == "PRIVATE KEY" {
      keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
      if err != nil {
         return Error(http.StatusInternalServerError, err.Error())
      }
      var ok bool
      privInterface, ok = keyInterface.(*rsa.PrivateKey)
      if !ok {
	 return Error(http.StatusInternalServerError, "Not RSA private key")
      }
   } else {
      return Error(http.StatusInternalServerError, "Invalid private key type")
   }

    privInterface.Precompute()

    if err := privInterface.Validate(); err != nil {
        return Error(http.StatusInternalServerError, err.Error())
    }

   ciphertext, err := stub.GetState(key)
   if err != nil {
      return Error(http.StatusInternalServerError, err.Error())
   }

   if val, err := rsa.DecryptPKCS1v15(rand.Reader, privInterface, []byte(ciphertext)); err != nil {
      return Error(http.StatusInternalServerError, err.Error())
   } else {
      return Success(http.StatusOK, "OK", val)
   }
}


