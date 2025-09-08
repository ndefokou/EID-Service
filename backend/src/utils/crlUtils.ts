import { pki, asn1 } from 'node-forge'; // Import asn1 directly
import axios from 'axios';
import { logger } from '../../utils/logger';
import { CertificateValidationError } from './certificateUtils';

/**
 * Interface representing a parsed CRL.
 * In a real-world scenario, this might be extended with more detailed CRL information.
 */
export interface Crl {
  isRevoked(serialNumber: string): boolean;
}

/**
 * Parses a CRL from a DER encoded buffer.
 * @param crlBuffer The DER encoded CRL as a Buffer.
 * @returns A Crl object.
 * @throws {CertificateValidationError} if the CRL cannot be parsed.
 */
export function parseCrl(crlBuffer: ArrayBuffer): Crl {
  try {
    const crlAsn1 = asn1.fromDer(Buffer.from(crlBuffer).toString('binary'));
    const crl = (pki as any).crlFromAsn1(crlAsn1);

    return {
      isRevoked: (serialNumber: string): boolean => {
        // node-forge serial numbers are typically in hexadecimal with a leading '0x'
        const formattedSerialNumber = serialNumber.startsWith('0x') ? serialNumber.substring(2).toUpperCase() : serialNumber.toUpperCase();
        
        for (const revokedCert of crl.revokedCertificates) {
          // Compare serial numbers, ensuring consistent formatting
          const revokedSerialNumber = revokedCert.serial.toUpperCase();
          if (revokedSerialNumber === formattedSerialNumber) {
            return true;
          }
        }
        return false;
      },
    };
  } catch (error) {
    logger.error(`Failed to parse CRL: ${(error as Error).message}`);
    throw new CertificateValidationError('Invalid CRL format or parsing error.');
  }
}

/**
 * Fetches a CRL from a given URL and parses it.
 * @param url The URL of the CRL distribution point.
 * @returns A promise that resolves to a Crl object if successful, or null if fetching/parsing fails.
 */
export async function fetchAndParseCrl(url: string): Promise<Crl | null> {
  try {
    logger.debug(`Fetching CRL from: ${url}`);
    const response = await axios.get(url, { responseType: 'arraybuffer' });
    return parseCrl(response.data);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      logger.warn(`Failed to fetch CRL from ${url}: ${error.message}. Status: ${error.response?.status}`);
    } else {
      logger.warn(`Failed to parse CRL from ${url}: ${(error as Error).message}`);
    }
    return null;
  }
}