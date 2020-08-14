/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"time"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/third_party/github.com/tjfoc/gmsm/sm2"
	"github.com/pkg/errors"
)

func (msp *bccspmsp) validateIdentity(id *identity) error {
	validationChain, err := msp.getCertificationChainForBCCSPIdentity(id)
	if err != nil {
		return errors.WithMessage(err, "could not obtain certification chain")
	}

	err = msp.validateIdentityAgainstChain(id, validationChain)
	if err != nil {
		return errors.WithMessage(err, "could not validate identity against certification chain")
	}

	err = msp.internalValidateIdentityOusFunc(id)
	if err != nil {
		return errors.WithMessage(err, "could not validate identity's OUs")
	}

	return nil
}

func (msp *bccspmsp) validateCAIdentity(id *identity) error {
	if factory.GetDefault().GetProviderName() == "SW" {
		if !id.cert.(*x509.Certificate).IsCA {
			return errors.New("Only CA identities can be validated")
		}

		validationChain, err := msp.getUniqueValidationChain(id.cert, msp.getValidityOptsForCert(id.cert))
		if err != nil {
			return errors.WithMessage(err, "could not obtain certification chain")
		}
		if len(validationChain.([]*x509.Certificate)) == 1 {
			// validationChain[0] is the root CA certificate
			return nil
		}

		return msp.validateIdentityAgainstChain(id, validationChain)
	} else {
		if !id.cert.(*sm2.Certificate).IsCA {
			return errors.New("Only CA identities can be validated")
		}

		validationChain, err := msp.getUniqueValidationChain(id.cert, msp.getValidityOptsForCert(id.cert))
		if err != nil {
			return errors.WithMessage(err, "could not obtain certification chain")
		}
		if len(validationChain.([]*sm2.Certificate)) == 1 {
			// validationChain[0] is the root CA certificate
			return nil
		}

		return msp.validateIdentityAgainstChain(id, validationChain)
	}
}

func (msp *bccspmsp) validateTLSCAIdentity(cert interface{}, optsInterface interface{}) error {
	if factory.GetDefault().GetProviderName() == "SW" {
		opts := optsInterface.(*x509.VerifyOptions)
		if !cert.(*x509.Certificate).IsCA {
			return errors.New("Only CA identities can be validated")
		}

		validationChain, err := msp.getUniqueValidationChain(cert, *opts)
		if err != nil {
			return errors.WithMessage(err, "could not obtain certification chain")
		}
		if len(validationChain.([]*x509.Certificate)) == 1 {
			// validationChain[0] is the root CA certificate
			return nil
		}

		return msp.validateCertAgainstChain(cert, validationChain)
	} else {
		opts := optsInterface.(*sm2.VerifyOptions)
		if !cert.(*sm2.Certificate).IsCA {
			return errors.New("Only CA identities can be validated")
		}

		validationChain, err := msp.getUniqueValidationChain(cert, *opts)
		if err != nil {
			return errors.WithMessage(err, "could not obtain certification chain")
		}
		if len(validationChain.([]*sm2.Certificate)) == 1 {
			// validationChain[0] is the root CA certificate
			return nil
		}

		return msp.validateCertAgainstChain(cert, validationChain)
	}
}

func (msp *bccspmsp) validateIdentityAgainstChain(id *identity, validationChain interface{}) error {
	return msp.validateCertAgainstChain(id.cert, validationChain)
}

func (msp *bccspmsp) validateCertAgainstChain(cert interface{}, validationChain interface{}) error {
	// here we know that the identity is valid; now we have to check whether it has been revoked

	if factory.GetDefault().GetProviderName() == "SW" {
		// identify the SKI of the CA that signed this cert
		SKI, err := getSubjectKeyIdentifierFromCert(validationChain.([]*x509.Certificate)[1])
		if err != nil {
			return errors.WithMessage(err, "could not obtain Subject Key Identifier for signer cert")
		}

		// check whether one of the CRLs we have has this cert's
		// SKI as its AuthorityKeyIdentifier
		for _, crl := range msp.CRL {
			aki, err := getAuthorityKeyIdentifierFromCrl(crl)
			if err != nil {
				return errors.WithMessage(err, "could not obtain Authority Key Identifier for crl")
			}

			// check if the SKI of the cert that signed us matches the AKI of any of the CRLs
			if bytes.Equal(aki, SKI) {
				// we have a CRL, check whether the serial number is revoked
				for _, rc := range crl.TBSCertList.RevokedCertificates {
					if rc.SerialNumber.Cmp(cert.(*x509.Certificate).SerialNumber) == 0 {
						// We have found a CRL whose AKI matches the SKI of
						// the CA (root or intermediate) that signed the
						// certificate that is under validation. As a
						// precaution, we verify that said CA is also the
						// signer of this CRL.
						err = validationChain.([]*x509.Certificate)[1].CheckCRLSignature(crl)
						if err != nil {
							// the CA cert that signed the certificate
							// that is under validation did not sign the
							// candidate CRL - skip
							mspLogger.Warningf("Invalid signature over the identified CRL, error %+v", err)
							continue
						}

						// A CRL also includes a time of revocation so that
						// the CA can say "this cert is to be revoked starting
						// from this time"; however here we just assume that
						// revocation applies instantaneously from the time
						// the MSP config is committed and used so we will not
						// make use of that field
						return errors.New("The certificate has been revoked")
					}
				}
			}
		}
	} else {
		// identify the SKI of the CA that signed this cert
		SKI, err := getSubjectKeyIdentifierFromCert(validationChain.([]*sm2.Certificate)[1])
		if err != nil {
			return errors.WithMessage(err, "could not obtain Subject Key Identifier for signer cert")
		}

		// check whether one of the CRLs we have has this cert's
		// SKI as its AuthorityKeyIdentifier
		for _, crl := range msp.CRL {
			aki, err := getAuthorityKeyIdentifierFromCrl(crl)
			if err != nil {
				return errors.WithMessage(err, "could not obtain Authority Key Identifier for crl")
			}

			// check if the SKI of the cert that signed us matches the AKI of any of the CRLs
			if bytes.Equal(aki, SKI) {
				// we have a CRL, check whether the serial number is revoked
				for _, rc := range crl.TBSCertList.RevokedCertificates {
					if rc.SerialNumber.Cmp(cert.(*sm2.Certificate).SerialNumber) == 0 {
						// We have found a CRL whose AKI matches the SKI of
						// the CA (root or intermediate) that signed the
						// certificate that is under validation. As a
						// precaution, we verify that said CA is also the
						// signer of this CRL.
						err = validationChain.([]*sm2.Certificate)[1].CheckCRLSignature(crl)
						if err != nil {
							// the CA cert that signed the certificate
							// that is under validation did not sign the
							// candidate CRL - skip
							mspLogger.Warningf("Invalid signature over the identified CRL, error %+v", err)
							continue
						}

						// A CRL also includes a time of revocation so that
						// the CA can say "this cert is to be revoked starting
						// from this time"; however here we just assume that
						// revocation applies instantaneously from the time
						// the MSP config is committed and used so we will not
						// make use of that field
						return errors.New("The certificate has been revoked")
					}
				}
			}
		}
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV1(id *identity) error {
	// Check that the identity's OUs are compatible with those recognized by this MSP,
	// meaning that the intersection is not empty.
	if len(msp.ouIdentifiers) > 0 {
		found := false

		for _, OU := range id.GetOrganizationalUnits() {
			certificationIDs, exists := msp.ouIdentifiers[OU.OrganizationalUnitIdentifier]

			if exists {
				for _, certificationID := range certificationIDs {
					if bytes.Equal(certificationID, OU.CertifiersIdentifier) {
						found = true
						break
					}
				}
			}
		}

		if !found {
			if len(id.GetOrganizationalUnits()) == 0 {
				return errors.New("the identity certificate does not contain an Organizational Unit (OU)")
			}
			return errors.Errorf("none of the identity's organizational units %s are in MSP %s", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV11(id *identity) error {
	// Run the same checks as per V1
	err := msp.validateIdentityOUsV1(id)
	if err != nil {
		return err
	}

	// Perform V1_1 additional checks:
	//
	// -- Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required
		return nil
	}

	// Make sure that the identity has only one of the special OUs
	// used to tell apart clients or peers.
	counter := 0
	for _, OU := range id.GetOrganizationalUnits() {
		// Is OU.OrganizationalUnitIdentifier one of the special OUs?
		var nodeOU *OUIdentifier
		switch OU.OrganizationalUnitIdentifier {
		case msp.clientOU.OrganizationalUnitIdentifier:
			nodeOU = msp.clientOU
		case msp.peerOU.OrganizationalUnitIdentifier:
			nodeOU = msp.peerOU
		default:
			continue
		}

		// Yes. Then, enforce the certifiers identifier is this is specified.
		// It is not specified, it means that any certification path is fine.
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, OU.CertifiersIdentifier) {
			return errors.Errorf("certifiersIdentifier does not match: %v, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
		counter++
		if counter > 1 {
			break
		}
	}
	if counter != 1 {
		return errors.Errorf("the identity must be a client or a peer identity to be valid, not a combination of them. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}

	return nil
}

func (msp *bccspmsp) validateIdentityOUsV143(id *identity) error {
	// Run the same checks as per V1
	err := msp.validateIdentityOUsV1(id)
	if err != nil {
		return err
	}

	// -- Check for OU enforcement
	if !msp.ouEnforcement {
		// No enforcement required
		return nil
	}

	// Make sure that the identity has only one of the special OUs
	// used to tell apart clients, peers and admins.
	counter := 0
	validOUs := make(map[string]*OUIdentifier)
	if msp.clientOU != nil {
		validOUs[msp.clientOU.OrganizationalUnitIdentifier] = msp.clientOU
	}
	if msp.peerOU != nil {
		validOUs[msp.peerOU.OrganizationalUnitIdentifier] = msp.peerOU
	}
	if msp.adminOU != nil {
		validOUs[msp.adminOU.OrganizationalUnitIdentifier] = msp.adminOU
	}
	if msp.ordererOU != nil {
		validOUs[msp.ordererOU.OrganizationalUnitIdentifier] = msp.ordererOU
	}

	for _, OU := range id.GetOrganizationalUnits() {
		// Is OU.OrganizationalUnitIdentifier one of the special OUs?
		nodeOU := validOUs[OU.OrganizationalUnitIdentifier]
		if nodeOU == nil {
			continue
		}

		// Yes. Then, enforce the certifiers identifier in this is specified.
		// If is not specified, it means that any certification path is fine.
		if len(nodeOU.CertifiersIdentifier) != 0 && !bytes.Equal(nodeOU.CertifiersIdentifier, OU.CertifiersIdentifier) {
			return errors.Errorf("certifiersIdentifier does not match: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
		}
		counter++
		if counter > 1 {
			break
		}
	}
	if counter != 1 {
		return errors.Errorf("the identity must be a client, a peer, an orderer or an admin identity to be valid, not a combination of them. OUs: %s, MSP: [%s]", OUIDs(id.GetOrganizationalUnits()), msp.name)
	}

	return nil
}

func (msp *bccspmsp) getValidityOptsForCert(cert interface{}) interface{} {
	// First copy the opts to override the CurrentTime field
	// in order to make the certificate passing the expiration test
	// independently from the real local current time.
	// This is a temporary workaround for FAB-3678

	if factory.GetDefault().GetProviderName() == "SW" {
		var tempOpts x509.VerifyOptions
		tempOpts.Roots = msp.opts.(*x509.VerifyOptions).Roots
		tempOpts.DNSName = msp.opts.(*x509.VerifyOptions).DNSName
		tempOpts.Intermediates = msp.opts.(*x509.VerifyOptions).Intermediates
		tempOpts.KeyUsages = msp.opts.(*x509.VerifyOptions).KeyUsages
		tempOpts.CurrentTime = cert.(*x509.Certificate).NotBefore.Add(time.Second)
		return tempOpts
	} else {
		var tempOpts sm2.VerifyOptions
		tempOpts.Roots = msp.opts.(*sm2.VerifyOptions).Roots
		tempOpts.DNSName = msp.opts.(*sm2.VerifyOptions).DNSName
		tempOpts.Intermediates = msp.opts.(*sm2.VerifyOptions).Intermediates
		tempOpts.KeyUsages = msp.opts.(*sm2.VerifyOptions).KeyUsages
		tempOpts.CurrentTime = cert.(*sm2.Certificate).NotBefore.Add(time.Second)
		return tempOpts
	}
}

/*
   This is the definition of the ASN.1 marshalling of AuthorityKeyIdentifier
   from https://www.ietf.org/rfc/rfc5280.txt

   AuthorityKeyIdentifier ::= SEQUENCE {
      keyIdentifier             [0] KeyIdentifier           OPTIONAL,
      authorityCertIssuer       [1] GeneralNames            OPTIONAL,
      authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }

   KeyIdentifier ::= OCTET STRING

   CertificateSerialNumber  ::=  INTEGER

*/

type authorityKeyIdentifier struct {
	KeyIdentifier             []byte  `asn1:"optional,tag:0"`
	AuthorityCertIssuer       []byte  `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber big.Int `asn1:"optional,tag:2"`
}

// getAuthorityKeyIdentifierFromCrl returns the Authority Key Identifier
// for the supplied CRL. The authority key identifier can be used to identify
// the public key corresponding to the private key which was used to sign the CRL.
func getAuthorityKeyIdentifierFromCrl(crl *pkix.CertificateList) ([]byte, error) {
	aki := authorityKeyIdentifier{}

	for _, ext := range crl.TBSCertList.Extensions {
		// Authority Key Identifier is identified by the following ASN.1 tag
		// authorityKeyIdentifier (2 5 29 35) (see https://tools.ietf.org/html/rfc3280.html)
		if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 35}) {
			_, err := asn1.Unmarshal(ext.Value, &aki)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal AKI")
			}

			return aki.KeyIdentifier, nil
		}
	}

	return nil, errors.New("authorityKeyIdentifier not found in certificate")
}

// getSubjectKeyIdentifierFromCert returns the Subject Key Identifier for the supplied certificate
// Subject Key Identifier is an identifier of the public key of this certificate
func getSubjectKeyIdentifierFromCert(cert interface{}) ([]byte, error) {
	var SKI []byte

	if factory.GetDefault().GetProviderName() == "SW" {
		for _, ext := range cert.(*x509.Certificate).Extensions {
			// Subject Key Identifier is identified by the following ASN.1 tag
			// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
			if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
				_, err := asn1.Unmarshal(ext.Value, &SKI)
				if err != nil {
					return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
				}

				return SKI, nil
			}
		}
	} else {
		for _, ext := range cert.(*sm2.Certificate).Extensions {
			// Subject Key Identifier is identified by the following ASN.1 tag
			// subjectKeyIdentifier (2 5 29 14) (see https://tools.ietf.org/html/rfc3280.html)
			if reflect.DeepEqual(ext.Id, asn1.ObjectIdentifier{2, 5, 29, 14}) {
				_, err := asn1.Unmarshal(ext.Value, &SKI)
				if err != nil {
					return nil, errors.Wrap(err, "failed to unmarshal Subject Key Identifier")
				}

				return SKI, nil
			}
		}
	}

	return nil, errors.New("subjectKeyIdentifier not found in certificate")
}
