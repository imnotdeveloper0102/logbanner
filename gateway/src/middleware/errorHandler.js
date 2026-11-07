const { AppError } = require('../errors');

function errorHandler(err, req, res, _next) {
  if (err instanceof AppError) {
    return res.status(err.status).json({
      error: { message: err.message, details: err.details || null },
    });
  }
  if (err && err.name === 'ZodError') {
    return res.status(400).json({
      error: {
        message: 'Validation failed',
        details: err.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        })),
      },
    });
  }
  console.error('Unhandled error', err);
  return res.status(500).json({ error: { message: 'Internal server error' } });
}

module.exports = errorHandler;
