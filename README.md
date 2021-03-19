# ABEBox
ABEBox is a *Cloud-assisted, privacy-preserving data storage system*. It is an overlay solution that can run over any 
existing data storage system. It provides data synchronisation, availability and privacy by a flexible, attribute-based 
end-to-end encryption.

It allows users to:
* share their data without having any information about the recipients;
* prevent access to unauthorised and revoked users;
* store their data on the Cloud without being afraid of disclosure.

All these features are handled by the system and transparent to the user, which only needs to define the access policies 
related to the new files he/she creates.

ABEBox implements **Attribute-based Access Control** (ABAC) through the use of **Attribute-based Encryption** (ABE), 
particularly *Ciphertext-Policy Attribute-based Encryption* (CP-ABE), allowing the **decoupling** of data provision and 
access control.

The system consists of three components:
* the **_Key Management System_** (KMS): a "trusted" entity that manages CP-ABE keys (creation, distribution, ...);
* the **_Client_**: a program, installed on user device, that hides to the user all the cryptographic operations;
* the **_Proxy Re-encryption Engine_** (PRE): a module that performs the *re-keying* operations required to revoke the
  access to no more authorised users or to refresh the data protection.
  
Because of the implemented re-keying mechanism, the PRE has no access to the content of the protected data, so it can be 
installed and managed by an external third party (the Cloud Provider itself or another one with access to the storage 
system).

ABEBox changes the trust model from the usual *full trust in the Cloud Provider* to a **_semi-trust in it and in the PRE
handler_**.

## Installation
In the folder of each ABEBox component you will find an appropriate file that will provide you with more detailed 
information about the component itself and its installation.