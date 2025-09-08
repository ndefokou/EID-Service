import { pki, asn1, util } from 'node-forge'; // Import 'util' for ByteStringBuffer
import { logger } from '../../utils/logger';

export class CertificateValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateValidationError';
  }
}
interface ForgeExtension {
  id: string;
  name?: string;
  critical?: boolean;
  value: any;
}

/**
 * Type guard for pki.CertificateExtension with a ByteStringBuffer value
 */
function isCertificateExtensionWithByteStringBufferValue(
  ext: ForgeExtension | undefined | null
): ext is ForgeExtension & { value: util.ByteStringBuffer } {
  return ext != null && ext.value instanceof util.ByteStringBuffer;
}

/**
 * Parses a PEM formatted certificate string into a node-forge certificate object.
 * @param certificatePem The certificate in PEM format.
 * @returns The parsed node-forge certificate object.
 * @throws {CertificateValidationError} if the certificate cannot be parsed.
 */
export function parseCertificate(certificatePem: string): pki.Certificate {
  try {
    return pki.certificateFromPem(certificatePem);
  } catch (error) {
    logger.error(`Failed to parse certificate: ${(error as Error).message}`);
    throw new CertificateValidationError('Invalid certificate format.');
  }
}

/**
 * Verifies a certificate chain against a set of trusted root certificates.
 * This function builds the certificate chain and validates its integrity and trustworthiness.
 * @param certificatePem The end-entity certificate in PEM format.
 * @param caCertsPem An array of CA certificates in PEM format that form the chain up to the root, or intermediate CAs.
 * @param trustAnchorsPem An array of trusted root certificates in PEM format.
 * @returns True if the certificate chain is valid, false otherwise.
 * @throws {CertificateValidationError} if the certificate chain validation fails.
 */
export function verifyCertificateChain(
  certificatePem: string,
  caCertsPem: string[],
  trustAnchorsPem: string[]
): boolean {
  try {
    const certificate = parseCertificate(certificatePem);
    const caStore = pki.createCaStore();

    // Add CA certificates to the CA store
    caCertsPem.forEach(caPem => {
      try {
        caStore.addCertificate(parseCertificate(caPem));
      } catch (error) {
        logger.warn(`Failed to add CA certificate to store: ${(error as Error).message}`);
      }
    });

    // Add trust anchors to the CA store
    trustAnchorsPem.forEach(anchorPem => {
      try {
        caStore.addCertificate(parseCertificate(anchorPem));
      } catch (error) {
        logger.warn(`Failed to add trust anchor certificate to store: ${(error as Error).message}`);
      }
    });

    // The callback for verifyCertificateChain expects `verified` to be `string | boolean`
    // and `certs` to be an array of `Certificate`. Adjusting the callback signature.
    pki.verifyCertificateChain(caStore, [certificate], (verified: string | boolean, depth: number, certs: pki.Certificate[]) => {
      if (verified !== true) { // 'verified' can be a string error message or false
        const errors = (typeof verified === 'string') ? [verified] : ['Unknown verification error'];
        logger.error(`Certificate chain verification failed at depth ${depth}: ${errors.join(', ')}`);
        throw new CertificateValidationError(`Certificate chain validation failed: ${errors.join(', ')}`);
      }
      return true; // Indicate success for this callback part
    });

    logger.debug('Certificate chain verification successful.');
    return true;
  } catch (error) {
    logger.error(`Error during certificate chain verification: ${(error as Error).message}`);
    if (error instanceof CertificateValidationError) {
      throw error;
    }
    throw new CertificateValidationError('An unexpected error occurred during certificate chain validation.');
  }
}

/**
 * Checks if a certificate is within its validity period.
 * @param certificatePem The certificate in PEM format.
 * @returns True if the certificate is currently valid, false otherwise.
 * @throws {CertificateValidationError} if the certificate validity check fails.
 */
export function checkCertificateValidityPeriod(certificatePem: string): boolean {
  try {
    const certificate = parseCertificate(certificatePem);
    const now = new Date();

    if (now < certificate.validity.notBefore) {
      logger.warn(`Certificate is not yet valid. Not before: ${certificate.validity.notBefore.toISOString()}`);
      throw new CertificateValidationError('Certificate is not yet valid.');
    }
    if (now > certificate.validity.notAfter) {
      logger.warn(`Certificate has expired. Not after: ${certificate.validity.notAfter.toISOString()}`);
      throw new CertificateValidationError('Certificate has expired.');
    }

    logger.debug('Certificate is within its validity period.');
    return true;
  } catch (error) {
    logger.error(`Error during certificate validity period check: ${(error as Error).message}`);
    if (error instanceof CertificateValidationError) {
      throw error;
    }
    throw new CertificateValidationError('An unexpected error occurred during validity period check.');
  }
}

/**
 * Extracts CRL distribution points from a certificate.
 * @param certificate The certificate object from which to extract distribution points.
 * @returns An array of URLs for CRL distribution points.
 */
function isAsn1(obj: any): obj is asn1.Asn1 {
  return obj && typeof obj === 'object' && 'tagClass' in obj && ('type' in obj || 'tagNumber' in obj) && 'value' in obj;
}

/**
 * Extracts CRL distribution points from a certificate.
 * @param certificate The certificate object from which to extract distribution points.
 * @returns An array of URLs for CRL distribution points.
 */
export function getCertificateDistributionPoints(certificate: pki.Certificate): string[] {
  const crlDistributionPoints: string[] = [];
  const crlExtension = certificate.getExtension('2.5.29.31') as ForgeExtension | undefined; // OID for CRL Distribution Points

  if (!isCertificateExtensionWithByteStringBufferValue(crlExtension)) {
    logger.debug('No valid CRL Distribution Points extension found.');
    return crlDistributionPoints;
  }

  try {
    // Parse the ASN.1 DER encoded value of the extension
    const decodedExtension = asn1.fromDer(crlExtension.value.bytes());

    // Ensure it's a SEQUENCE OF DistributionPoint
    if (isAsn1(decodedExtension) &&
        decodedExtension.tagClass === asn1.Class.UNIVERSAL &&
        decodedExtension.type === asn1.Type.SEQUENCE &&
        Array.isArray(decodedExtension.value)) {

      for (const distributionPoint of decodedExtension.value) {
        // Each distributionPoint should be a SEQUENCE
        if (isAsn1(distributionPoint) &&
            distributionPoint.tagClass === asn1.Class.UNIVERSAL &&
            distributionPoint.type === asn1.Type.SEQUENCE &&
            Array.isArray(distributionPoint.value)) {

          for (const dpComponent of distributionPoint.value) {
            // Look for the distributionPoint field, which is [0] CONTEXT_SPECIFIC
            if (isAsn1(dpComponent) && dpComponent.tagClass === asn1.Class.CONTEXT_SPECIFIC && (dpComponent as any).tagNumber === 0) {
              // Access the inner structure (DistributionPointName) which is the first element of dpComponent.value
              const distributionPointName = Array.isArray(dpComponent.value) ? dpComponent.value[0] : null;

              // Check if DistributionPointName is fullName [0] GeneralNames
              if (isAsn1(distributionPointName) &&
                  distributionPointName.tagClass === asn1.Class.CONTEXT_SPECIFIC &&
                  (distributionPointName as any).tagNumber === 0 && // This [0] indicates fullName
                  Array.isArray(distributionPointName.value)) {

                // GeneralNames is a SEQUENCE, which is the first element of distributionPointName.value
                const generalNamesSequence = Array.isArray(distributionPointName.value) ? distributionPointName.value[0] : null;

                if (isAsn1(generalNamesSequence) && Array.isArray(generalNamesSequence.value)) {
                  for (const generalName of generalNamesSequence.value) {
                    // Look for uniformResourceIdentifier [6] CONTEXT_SPECIFIC
                    if (isAsn1(generalName) && generalName.tagClass === asn1.Class.CONTEXT_SPECIFIC && (generalName as any).tagNumber === 6) {
                      const uri = generalName.value;
                      if (typeof uri === 'string') {
                        crlDistributionPoints.push(uri);
                      } else if (uri instanceof util.ByteStringBuffer) {
                        crlDistributionPoints.push(uri.toString());
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      logger.warn('CRL Distribution Points extension value is not a SEQUENCE of DistributionPoint as expected.');
    }
  } catch (error) {
    logger.error(`Error parsing CRL Distribution Points extension: ${(error as Error).message}`);
    // Log the error and return partial results or an empty array.
  }

  return crlDistributionPoints;
}

/**
 * Extracts OCSP responder URI from a certificate.
 * @param certificate The certificate object from which to extract the OCSP URI.
 * @returns The OCSP responder URI, or null if not found.
 */
export function getOcspResponderUri(certificate: pki.Certificate): string | null {
  const authorityInfoAccess = certificate.getExtension('1.3.6.1.5.5.7.1.1') as ForgeExtension | undefined; // OID for Authority Information Access

  if (!isCertificateExtensionWithByteStringBufferValue(authorityInfoAccess)) {
    logger.debug('No valid Authority Information Access extension found.');
    return null;
  }

  try {
    // node-forge's extension.value is a ByteStringBuffer
    const decodedExtension = asn1.fromDer(authorityInfoAccess.value.bytes());

    if (isAsn1(decodedExtension) &&
        decodedExtension.tagClass === asn1.Class.UNIVERSAL &&
        decodedExtension.type === asn1.Type.SEQUENCE &&
        Array.isArray(decodedExtension.value)) {

      for (const accessDescription of decodedExtension.value) {
        if (isAsn1(accessDescription) &&
            accessDescription.tagClass === asn1.Class.UNIVERSAL &&
            accessDescription.type === asn1.Type.SEQUENCE &&
            Array.isArray(accessDescription.value)) {

          const accessMethod = accessDescription.value[0];
          const accessLocation = accessDescription.value[1];

          // Check for id-ad-ocsp (OID 1.3.6.1.5.5.7.48.1)
          if (isAsn1(accessMethod) && accessMethod.type === asn1.Type.OID && accessMethod.value === '1.3.6.1.5.5.7.48.1') {
            // Look for uniformResourceIdentifier [6] CONTEXT_SPECIFIC in accessLocation
            if (isAsn1(accessLocation) &&
                accessLocation.tagClass === asn1.Class.CONTEXT_SPECIFIC &&
                (accessLocation as any).tagNumber === 6) {
              const uri = accessLocation.value;
              if (typeof uri === 'string') {
                return uri;
              } else if (uri instanceof util.ByteStringBuffer) {
                return uri.toString();
              }
            }
          }
        }
      }
    }
  } catch (error) { // This catch now covers the entire ASN.1 decoding and parsing
    logger.error(`Error decoding or parsing Authority Information Access extension: ${(error as Error).message}`);
  }

  return null;
}

/**
 * Builds a mock OCSP request for a given certificate.
 * This is a placeholder and should be replaced with a real OCSP request building library.
 * @param certificate The parsed certificate object.
 * @returns A Buffer representing the mock OCSP request.
 */
export function buildMockOcspRequest(certificate: pki.Certificate): Buffer {
  logger.debug(`Building mock OCSP request for serial: ${certificate.serialNumber}`);
  const ocspRequestData = `mock OCSP request data for serial: ${certificate.serialNumber}`;
  return Buffer.from(ocspRequestData);
}