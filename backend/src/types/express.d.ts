// This file is used to augment Express.js types, typically to add custom properties
// to the Request, Response, or other Express objects that your middleware might add.

declare namespace Express {
  interface Request {
    // Add any custom properties you might attach to the Request object here.
    // For example, if you have a custom authentication middleware that adds 'user',
    // or a rate limiting middleware that adds 'rateLimitInfo'.
    rateLimit?: {
      limit: number;
      current: number;
      remaining: number;
      resetTime?: Date;
    };
    // If you have a request ID or correlation ID that you generate
    reqId?: string;
  }

  // You can also augment other Express interfaces like Response or Application if needed
  // interface Response {
  //   myCustomSend?: (data: any) => void;
  // }
}