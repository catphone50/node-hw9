import jwt from "jsonwebtoken";

export default function MustChangePasswordMiddleware(req, res, next) {
  if (req.user && req.user.mustChangePassword) {
    return res.redirect(`/change-password/${req.user.id}`);
  }
  next();
}
