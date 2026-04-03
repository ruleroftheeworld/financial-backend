class AppError extends Error {
  constructor(message, statusCode = 500, code = 'INTERNAL_ERROR', details = null) {
    super(message);

    this.statusCode = statusCode;
    this.code = code;
    this.details = details; // optional extra info (validation errors, etc.)

    // Operational vs programming error
    this.isOperational = true;

    // Timestamp (useful for logs / debugging)
    this.timestamp = new Date().toISOString();

    // Maintain proper stack trace
    Error.captureStackTrace(this, this.constructor);
  }
}

export default AppError;