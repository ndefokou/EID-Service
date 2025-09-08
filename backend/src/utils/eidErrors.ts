export class EidVerificationError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode: number = 400) {
    super(message);
    this.name = 'EidVerificationError';
    this.statusCode = statusCode;
  }
}

export class EidSessionError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode: number = 404) {
    super(message);
    this.name = 'EidSessionError';
    this.statusCode = statusCode;
  }
}

export class EidConfigurationError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode: number = 500) {
    super(message);
    this.name = 'EidConfigurationError';
    this.statusCode = statusCode;
  }
}

export class EidCallbackError extends Error {
  public statusCode: number;
  constructor(message: string, statusCode: number = 400) {
    super(message);
    this.name = 'EidCallbackError';
    this.statusCode = statusCode;
  }
}