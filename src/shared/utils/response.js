const successResponse = (res, data = {}, message = 'Success', statusCode = 200) => {
  return res.status(statusCode).json({
    success: true,
    code: 'SUCCESS',
    message,
    data,
    timestamp: new Date().toISOString(),
  });
};

const errorResponse = (
  res,
  message = 'An error occurred',
  statusCode = 500,
  code = 'ERROR',
  errors = null
) => {
  const response = {
    success: false,
    code,
    message,
    timestamp: new Date().toISOString(),
  };

  if (errors) response.errors = errors;

  return res.status(statusCode).json(response);
};

export { successResponse, errorResponse };