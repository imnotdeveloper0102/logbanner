class AppError extends Error {
  constructor(status, message, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

function badRequest(message, details) {
  return new AppError(400, message, details);
}

function unauthorized(message = 'Authentication required') {
  return new AppError(401, message);
}

function forbidden(message = 'Not allowed') {
  return new AppError(403, message);
}

function notFound(message = 'Not found') {
  return new AppError(404, message);
}

function conflict(message) {
  return new AppError(409, message);
}

module.exports = { AppError, badRequest, unauthorized, forbidden, notFound, conflict };
