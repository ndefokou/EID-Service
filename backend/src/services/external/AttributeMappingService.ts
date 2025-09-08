import { logger } from '@root/utils/logger';

/**
 * Interface representing the structure of raw eID attributes received from the eID server.
 * This should ideally reflect the actual attributes defined by TR-03124 or your eID server's response.
 * For demonstration, we'll include common attributes.
 */
export interface RawEidAttributes {
  // Example attributes from TR-03124 or eID server response
  // These are often nested or have specific naming conventions
  givenNames?: string;
  familyName?: string;
  birthName?: string;
  dateOfBirth?: string; // YYYY-MM-DD
  placeOfBirth?: string;
  nationality?: string;
  address?: {
    street?: string;
    houseNumber?: string;
    zipCode?: string;
    city?: string;
    country?: string;
  };
  // Add other relevant eID attributes as needed
  // e.g., documentType, issuingAuthority, etc.
}

/**
 * Interface representing the internal user profile attributes in your application.
 * This should be a simplified, flattened, and application-specific view of user data.
 */
export interface MappedUserAttributes {
  firstName?: string;
  lastName?: string;
  dateOfBirth?: Date; // Converted to Date object
  addressStreet?: string;
  addressHouseNumber?: string;
  addressZipCode?: string;
  addressCity?: string;
  addressCountry?: string;
  // Add other mapped attributes as needed for your internal user model
}

/**
 * Service responsible for mapping raw eID attributes received from the eID server
 * to the application's internal user attribute structure.
 * This ensures data minimization and provides a consistent internal data format.
 */
export class AttributeMappingService {
  /**
   * Maps raw eID attributes to a simplified, application-specific user attribute structure.
   * Only attributes necessary for the application's functionality should be mapped and retained.
   * @param rawAttributes The raw attribute object received from the eID server.
   * @returns A mapped object containing selected user attributes.
   */
  public mapEidAttributesToUser(rawAttributes: RawEidAttributes): MappedUserAttributes {
    logger.debug('Starting eID attribute mapping process.');

    const mappedAttributes: MappedUserAttributes = {};

    // Example mapping logic:
    if (rawAttributes.givenNames) {
      mappedAttributes.firstName = rawAttributes.givenNames;
    }
    if (rawAttributes.familyName) {
      mappedAttributes.lastName = rawAttributes.familyName;
    }
    if (rawAttributes.dateOfBirth) {
      try {
        mappedAttributes.dateOfBirth = new Date(rawAttributes.dateOfBirth);
      } catch (error) {
        logger.warn(`Failed to parse dateOfBirth "${rawAttributes.dateOfBirth}":`, error);
      }
    }
    if (rawAttributes.address) {
      if (rawAttributes.address.street) {
        mappedAttributes.addressStreet = rawAttributes.address.street;
      }
      if (rawAttributes.address.houseNumber) {
        mappedAttributes.addressHouseNumber = rawAttributes.address.houseNumber;
      }
      if (rawAttributes.address.zipCode) {
        mappedAttributes.addressZipCode = rawAttributes.address.zipCode;
      }
      if (rawAttributes.address.city) {
        mappedAttributes.addressCity = rawAttributes.address.city;
      }
      if (rawAttributes.address.country) {
        mappedAttributes.addressCountry = rawAttributes.address.country;
      }
    }
    // Add more mapping rules as per TR-03124 and your application's needs

    logger.info('eID attributes successfully mapped to internal user attributes.');
    logger.debug('Mapped attributes:', mappedAttributes);
    return mappedAttributes;
  }
}