package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"

	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func main() {
	help := flag.Bool("help", false, "Option, Imprime Informação ao usuário")
	host := flag.String("host", "", "Requerido flag, ip associado ao certificado.")
	serverCert := flag.String("srvcert", "", "Requerido, O nome do arquivo do certificado para o servidor")
	caCert := flag.String("cacert", "", "Requerido, O nome da CA que assinou o certificado do cliente")
	srvKey := flag.String("srvkey", "", "Requerido, O nome do arquivo com a chave privada")

	flag.Parse()

	usage := `usage:
	
proxylog -host <hostname> -srvcert <serverCertFile> -cacert <caCertFile> -srvkey <serverPrivateKeyFile> [-help>]

Options:
  -help		Imprime esta mensagem
  -host		Requerido, IP do servidor
  -srvcert	Requerido, O nome do arquivo de certificado do servidor
  -cacert	Requerido, O nome do CA que assinou o certificado do cliente`

	if *help == true {
		fmt.Println(usage)
		return
	}

	if *host == "" || *serverCert == "" || *caCert == "" || *srvKey == "" {
		log.Fatalf("Um ou mais campos requeridos estão faltando: \n%s", usage)
	}

	server := &http.Server{
		Addr:         ":443",
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 10 * time.Second,
		TLSConfig:    getTLSConfig(*host, *caCert),
	}

	http.HandleFunc("/api/logs3", HandleLogS3)

	log.Printf("Starting HTTPS server on host %s and port 443", *host)
	if err := server.ListenAndServeTLS(*serverCert, *srvKey); err != nil {
		log.Fatal(err)
	}
}

func HandleLogS3(w http.ResponseWriter, r *http.Request) {
	log.Printf("Receive %s request for host %s from IP address %s and X-FORWARDED-FOR %s",
	r.Method, r.Host, r.RemoteAddr, r.Header.Get("X-FORWARDED-FOR"))

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
			body = []byte(fmt.Sprintf("error reading request body: %s", err))
		}

		resp := fmt.Sprintf("Hello, %s from Advanced Server!", body)
		w.Write([]byte(resp))
		log.Printf("Advanced Server: Send response %s", resp)
	})
}

func getTLSConfig(host, caCertFile string) *tls.Config {
	var caCert []byte
	var err error
	var caCertPool *x509.CertPool

	caCert, err = ioutil.ReadFile(caCertFile)
	if err != nil {
		log.Fatal("Error opening cert file", caCertFile, ", error", err)
	}

	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		ServerName: host,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}
}
