# JWT_Go_auth

Simple JWT RS256 authenticator

Please create private and public RSA keys by follwing commends:

openssl genrsa -out cert/id_rsa 4096
openssl rsa -in cert/id_rsa -pubout -out cert/id_rsa.pub
