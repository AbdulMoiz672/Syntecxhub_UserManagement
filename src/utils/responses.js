function successResponse(data, statusCode = 200) {
  return {
    statusCode,
    body: { data }
  };
}

function errorResponse(code, message, details = null, statusCode = 400) {
  const error = { code, message };
  if (details) {
    error.details = details;
  }

  return {
    statusCode,
    body: { error }
  };
}

module.exports = { successResponse, errorResponse };
