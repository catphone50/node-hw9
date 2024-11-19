export default function logRequest(req, res, next) {
  console.log(`Recived ${req.method} request for${req.url}`);
  next();
}
