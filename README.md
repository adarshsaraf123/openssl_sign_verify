DER: Distinguished Encoding Rules
---------------------------------

Encode the data that makes up a certificate; the encoded data is still in bytes.

PEM: Privacy Enchanced Mail
----------------------------

Encode binary data as a string(ASCII armor); header and footer line; for certificate data, it will just contain the base64 encoding of the DER certificate; mail cannot contain bytes.
